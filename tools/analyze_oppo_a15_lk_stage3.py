#!/usr/bin/env python3
"""Reachability-guided, read-only ARM/Thumb analysis for Oppo A15 MTK LK.

Unlike a linear sweep, this follows control-flow from explicit entry seeds and
only decodes reachable basic blocks. It never modifies the input image.
"""
import os, struct, hashlib
from pathlib import Path
from collections import deque, defaultdict
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

IMAGE = Path(os.getenv("IMAGE_PATH", "oppo-a15-signed-test.img"))
BASE = int(os.getenv("LOAD_BASE", "0x48000000"), 0)
PREFIX = int(os.getenv("PAYLOAD_OFFSET", "0x200"), 0)
ENTRY = int(os.getenv("ENTRY_ADDRESS", "0x480028B0"), 0)
OUT = Path("menu-xref-stage3")
OUT.mkdir(exist_ok=True)
raw = IMAGE.read_bytes()
payload = raw[PREFIX:]
END = BASE + len(payload)
if len(payload) < 4:
    raise SystemExit("payload too small")

MENU_TERMS = [
    b"Select Boot Mode:", b"VOLUME_UP to select", b"Recovery    Mode",
    b"Fastboot    Mode", b"Normal      Boot", b"Unlock bootloader?",
    b"lock bootloader?", b"Volume UP/Down buttons",
    b"Yes (Volume Down):Unlock", b"No (Volume UP):Do not unlock bootloader.",
    b"download", b"recovery", b"boot-fastboot", b"boot-recovery",
    b"reboot-bootloader", b"reboot-recovery", b"reboot-fastboot",
    b"singlebootloader", b"Set_RTC_Fastboot_Mode", b"mt_power_off new",
]
strings = {}
for term in MENU_TERMS:
    off = payload.find(term)
    if off >= 0:
        strings[BASE + off] = term.decode("ascii", "replace")
targets = set(strings)

def u32_at_va(va):
    off = va - BASE
    if 0 <= off <= len(payload) - 4:
        return struct.unpack_from("<I", payload, off)[0]
    return None

# Record exact pointer-table entries that point at one of the strings.
ptr_entries = defaultdict(list)
for off in range(0, len(payload) - 3, 4):
    value = struct.unpack_from("<I", payload, off)[0]
    if value in targets:
        ptr_entries[BASE + off].append(value)

# Worklist items are (address, ISA mode). Seed both states at the known
# platform-init entry because the prior report did not prove its ISA state.
queue = deque([(ENTRY & ~1, "thumb"), (ENTRY & ~3, "arm")])
seen = set()
insns = {}
functions = set()
call_edges = set()
xrefs = []
literal_loads = []
mov_parts = defaultdict(dict)
MAX_INSNS = int(os.getenv("MAX_INSTRUCTIONS", "500000"))

def in_image(addr):
    return BASE <= (addr & ~1) < END

def dis_one(addr, mode):
    off = (addr & ~1) - BASE
    if off < 0 or off >= len(payload):
        return None
    cs_mode = (CS_MODE_THUMB if mode == "thumb" else CS_MODE_ARM) | CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, cs_mode)
    md.detail = True
    size = 4 if mode == "arm" else 4
    it = md.disasm(payload[off:off+size], addr & ~1, count=1)
    return next(it, None)

def add_target(addr, mode):
    if in_image(addr):
        queue.append((addr & ~1, mode))

while queue and len(insns) < MAX_INSNS:
    start, mode = queue.popleft()
    if not in_image(start):
        continue
    functions.add((start, mode))
    pc = start
    block_seen = set()
    while in_image(pc) and (pc, mode) not in seen and pc not in block_seen and len(insns) < MAX_INSNS:
        block_seen.add(pc)
        ins = dis_one(pc, mode)
        if ins is None or ins.size not in (2, 4):
            break
        seen.add((pc, mode))
        insns[(pc, mode)] = ins
        next_pc = pc + ins.size
        m = ins.mnemonic.lower()
        ops = ins.operands

        # PC-relative literal LDR: resolve its pool slot and pointer value.
        if m.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM and ops[1].mem.base == ARM_REG_PC:
            if mode == "thumb":
                pc_val = (pc + 4) & ~3
            else:
                pc_val = pc + 8
            slot = (pc_val + ops[1].mem.disp) & 0xffffffff
            val = u32_at_va(slot)
            if val is not None:
                literal_loads.append((pc, mode, slot, val, ins.mnemonic, ins.op_str))
                if val in targets:
                    xrefs.append((pc, mode, val, "literal-value", ins.mnemonic, ins.op_str))
                if slot in ptr_entries:
                    for target in ptr_entries[slot]:
                        xrefs.append((pc, mode, target, "pointer-table-slot", ins.mnemonic, ins.op_str))
        # ADR resolves a direct address.
        if m == "adr" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            val = ops[1].imm & 0xffffffff
            if val in targets:
                xrefs.append((pc, mode, val, "adr", ins.mnemonic, ins.op_str))
        # Keep MOVW/MOVT values per mode/register and report exact target matches.
        if m in ("movw", "movt") and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            reg = ops[0].reg
            mov_parts[(mode, reg)][m] = (ops[1].imm & 0xffff, pc)
            pair = mov_parts[(mode, reg)]
            if "movw" in pair and "movt" in pair:
                value = (pair["movt"][0] << 16) | pair["movw"][0]
                if value in targets:
                    xrefs.append((pc, mode, value, "movw-movt", ins.mnemonic, ins.op_str))

        # Direct calls only (BL/BLX), not ordinary B branches.
        if m in ("bl", "blx") and ops and ops[0].type == ARM_OP_IMM:
            dest = ops[0].imm & 0xffffffff
            target_mode = "thumb" if (m == "blx" and mode == "arm") or (dest & 1) else mode
            dest &= ~1
            if in_image(dest):
                call_edges.add((pc, mode, dest, target_mode))
                add_target(dest, target_mode)

        # Conditional/unconditional direct branches. Do not treat all B as calls.
        is_branch = m == "b" or m.startswith("b.")
        if is_branch and ops and ops[0].type == ARM_OP_IMM:
            dest = ops[0].imm & 0xffffffff
            add_target(dest, "thumb" if (dest & 1) else mode)
            # Conditional branches retain fall-through; unconditional B ends block.
            cond = m not in ("b", "b.w")
            if not cond:
                break
        # Return / indirect control transfer ends this block.
        if m in ("bx", "bxj") and ops and "lr" in ins.op_str:
            break
        if m in ("pop", "ldmia", "ldm") and "pc" in ins.op_str:
            break
        if m.startswith("ldr") and ops and ops[0].type == ARM_OP_REG and ins.reg_name(ops[0].reg) == "pc":
            break
        pc = next_pc

# Export reachable instructions, function/call graph, string xrefs, pointer table.
def write_lines(name, lines):
    (OUT / name).write_text("\n".join(lines) + ("\n" if lines else ""))

write_lines("reachable_code.txt", [
    f"{mode.upper()} 0x{addr:08X}: {ins.mnemonic:8} {ins.op_str} [{ins.bytes.hex()}]"
    for (addr, mode), ins in sorted(insns.items())
])
write_lines("function_seeds.txt", [
    f"{mode.upper()} 0x{addr:08X}" for addr, mode in sorted(functions)
])
write_lines("call_graph.txt", [
    f"{mode.upper()} call@0x{site:08X} -> {tm.upper()} 0x{dest:08X}"
    for site, mode, dest, tm in sorted(call_edges)
])
write_lines("string_xrefs.txt", [
    f"{mode.upper()} site=0x{site:08X} -> 0x{target:08X} [{strings[target]}] via={kind} {mn} {op}"
    for site, mode, target, kind, mn, op in sorted(set(xrefs))
])
write_lines("literal_loads.txt", [
    f"{mode.upper()} site=0x{site:08X} slot=0x{slot:08X} value=0x{value:08X} {mn} {op}"
    for site, mode, slot, value, mn, op in literal_loads
])
write_lines("string_pointer_table.txt", [
    f"slot=0x{slot:08X} file_off=0x{PREFIX + slot - BASE:X} -> 0x{value:08X} {strings[value]}"
    for slot, vals in sorted(ptr_entries.items()) for value in vals
])
summary = [
    "Oppo A15 LK stage-3 reachability-guided static analysis (READ ONLY)",
    f"image={IMAGE}",
    f"sha256={hashlib.sha256(raw).hexdigest()}",
    f"size={len(raw)} payload_offset=0x{PREFIX:X} load_base=0x{BASE:08X}",
    f"entry_seed=0x{ENTRY:08X} isa_seeds=ARM+THUMB",
    f"menu_and_boot_strings_found={len(strings)}",
    f"aligned_pointer_table_hits={sum(map(len, ptr_entries.values()))}",
    f"reachable_instructions={len(insns)}",
    f"function_entry_seeds={len(functions)}",
    f"direct_call_edges={len(call_edges)}",
    f"reachable_string_xrefs={len(set(xrefs))}",
    f"literal_loads={len(literal_loads)}",
    "",
    "IMPORTANT: this is a conservative reachability pass from a single unverified entry seed.",
    "A seed is not proof of a function boundary; ARM/Thumb state may be wrong for some paths.",
    "No image bytes are changed. Do not flash based on this report alone."
]
(OUT / "SUMMARY.txt").write_text("\n".join(summary) + "\n")
print("\n".join(summary))
