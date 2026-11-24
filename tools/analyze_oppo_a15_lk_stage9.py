#!/usr/bin/env python3
"""Oppo A15 LK Stage 9: cross-reference boot menu flows, key helper and boot strings.
Read-only static analysis. Does not modify the LK image.
"""
import os, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

IMAGE = Path(os.getenv("IMAGE_PATH", "oppo-a15-signed-test.img"))
BASE = int(os.getenv("LOAD_BASE", "0x48000000"), 0)
PREFIX = int(os.getenv("PAYLOAD_OFFSET", "0x200"), 0)
raw = IMAGE.read_bytes()
data = raw[PREFIX:]
OUT = Path("menu-trace-stage9")
OUT.mkdir(exist_ok=True)

TARGETS = {
    0x4802E960: "unlock_confirmation_flow",
    0x4802EA84: "lock_confirmation_flow",
    0x4802E5EC: "boot_mode_menu_renderer",
    0x480050EC: "key_input_helper",
    0x480216D0: "boot_recovery_string",
    0x480216DC: "boot_fastboot_string",
}
md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md_t.detail = True
md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN); md_a.detail = True

def va_to_off(va):
    return va - BASE - PREFIX

def dump_range(start, size, filename, mode="thumb"):
    off = start - BASE - PREFIX
    if off < 0 or off >= len(data):
        return
    md = md_t if mode == "thumb" else md_a
    ins = md.disasm(data[off:min(len(data), off + size)], start)
    lines = [f"Disassembly {mode} from 0x{start:08X}"]
    lines.extend(f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}" for i in ins)
    (OUT / filename).write_text("\n".join(lines) + "\n")

# Scan aligned instruction streams for direct branches/calls to known code targets.
# This is deliberately reported as candidates because arbitrary offsets may decode as code.
direct = []
for mode, md, step in (("thumb", md_t, 2), ("arm", md_a, 4)):
    for off in range(0, len(data) - 4, step):
        addr = BASE + PREFIX + off
        for ins in md.disasm(data[off:off+4], addr, count=1):
            if ins.mnemonic.lower() in ("bl", "blx", "b", "b.w"):
                for op in ins.operands:
                    if op.type == 2:
                        dest = op.imm & 0xFFFFFFFF
                        if dest in TARGETS and dest <= 0x4802FFFF:
                            direct.append((mode, ins.address, ins.mnemonic, dest, ins.op_str))
            break

# Search exact little-endian code/data pointers, including Thumb-bit variants.
pointer_hits = []
for va, label in TARGETS.items():
    forms = {va, va | 1}
    for value in forms:
        needle = struct.pack("<I", value)
        pos = 0
        while True:
            pos = data.find(needle, pos)
            if pos < 0: break
            pointer_hits.append((BASE + PREFIX + pos, value, label))
            pos += 1

# References to menu strings and other boot mode text. Report raw aligned pointer candidates.
STRING_TARGETS = {
    0x4808C33C: "Select Boot Mode",
    0x4808C34E: "Volume key instructions",
    0x4808C37C: "Recovery Mode",
    0x4808C3A0: "Fastboot Mode",
    0x4808C3C4: "Normal Boot",
    0x480216D0: "boot-recovery",
    0x480216DC: "boot-fastboot",
}
string_ptr_hits = []
for va, label in STRING_TARGETS.items():
    for value in (va, va | 1):
        needle = struct.pack("<I", value)
        pos = 0
        while True:
            pos = data.find(needle, pos)
            if pos < 0: break
            string_ptr_hits.append((BASE + PREFIX + pos, value, label))
            pos += 1

# Focused windows for known routines and likely boot dispatch string area.
dump_range(0x4802E900, 0x320, "unlock_lock_flows.txt", "thumb")
dump_range(0x480050A0, 0x180, "key_input_helper_area.txt", "thumb")
dump_range(0x48021680, 0x180, "boot_dispatch_strings_area.txt", "thumb")
dump_range(0x4802E5A0, 0x120, "menu_renderer_area.txt", "thumb")
dump_range(0x4802E900, 0x320, "unlock_lock_flows_arm.txt", "arm")

lines = [
    "Oppo A15 LK Stage 9 - cross-reference and boot-path candidates (read-only)",
    f"image={IMAGE}",
    f"sha256={hashlib.sha256(raw).hexdigest()}",
    f"size={len(raw)} payload_offset=0x{PREFIX:X} load_base=0x{BASE:08X}",
    f"direct_branch_candidates={len(direct)}",
    f"literal_pointer_candidates={len(pointer_hits)}",
    f"menu_and_boot_string_pointer_candidates={len(string_ptr_hits)}",
    "",
    "DIRECT BRANCH/CALL CANDIDATES:",
]
lines += [f"{mode} 0x{site:08X}: {mn} {op} -> 0x{dest:08X} ({TARGETS[dest]})"
          for mode, site, mn, dest, op in direct]
lines += ["", "RAW POINTER CANDIDATES:"]
lines += [f"0x{site:08X}: word=0x{value:08X} -> {label}"
          for site, value, label in pointer_hits]
lines += ["", "MENU/BOOT STRING POINTER CANDIDATES:"]
lines += [f"0x{site:08X}: word=0x{value:08X} -> {label}"
          for site, value, label in string_ptr_hits]
lines += [
    "",
    "INTERPRETATION LIMITS:",
    "- Arbitrary-offset ARM/Thumb decoding can produce false positives; validate each hit in a coherent function.",
    "- Raw pointer matches may be data tables, relocations, or accidental byte matches; inspect surrounding bytes.",
    "- No direct hit does not rule out indirect calls, computed addresses, callbacks, or omitted payload regions.",
    "- Key helper semantics and boot-mode dispatch are not inferred from names alone.",
    "- No LK bytes modified.",
]
(OUT / "SUMMARY.txt").write_text("\n".join(lines) + "\n")
print((OUT / "SUMMARY.txt").read_text())
