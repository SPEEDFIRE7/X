#!/usr/bin/env python3
"""Read-only deep inspection of the Oppo A15 LK boot-mode/unlock UI region.

Reports references to the embedded menu strings in both ARM and Thumb modes.
This is candidate analysis only; it never patches the LK image.
"""
import hashlib, os, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

IMAGE = Path(os.environ.get("IMAGE_PATH", "oppo-a15-signed-test.img"))
BASE = int(os.environ.get("LOAD_BASE", "0x48000000"), 0)
PREFIX = int(os.environ.get("PAYLOAD_OFFSET", "0x200"), 0)
OUT = Path("menu-deep-analysis")
OUT.mkdir(exist_ok=True)
if not IMAGE.is_file():
    raise SystemExit(f"Missing LK image: {IMAGE}")
blob = IMAGE.read_bytes()
if len(blob) <= PREFIX:
    raise SystemExit("Payload offset exceeds image")
payload = blob[PREFIX:]
sha = hashlib.sha256(blob).hexdigest()

# Exact string addresses already observed in the read-only reconnaissance.
needles = [
    b"Select Boot Mode:",
    b"[VOLUME_UP to select.  VOLUME_DOWN is OK.]",
    b"[Recovery    Mode]",
    b"[Fastboot    Mode]",
    b"Unlock bootloader?",
    b"Press the Volume UP/Down buttons to select Yes or No.",
    b"Yes (Volume Down):Unlock",
    b"No (Volume UP):Do not unlock bootloader.",
    b"lock bootloader?",
    b"Yes (Volume Down):Lock bootloader.",
    b"No (Volume UP):Do not lock bootloader.",
]
targets = {}
string_rows = []
for s in needles:
    pos = payload.find(s)
    if pos >= 0:
        va = BASE + pos
        targets[va] = s.decode("ascii", "replace")
        string_rows.append((va, PREFIX + pos, s.decode("ascii", "replace")))
    else:
        string_rows.append((None, None, s.decode("ascii", "replace") + " [NOT FOUND]"))

(OUT / "menu_strings.txt").write_text(
    "\n".join(f"VA=0x{va:08X} file_off=0x{off:X} {s}" if va is not None else s
              for va, off, s in string_rows) + "\n"
)

# Search literal absolute pointers in the whole file.
pointer_rows = []
for off in range(PREFIX, len(blob) - 3, 4):
    v = struct.unpack_from("<I", blob, off)[0]
    if v in targets:
        pointer_rows.append((BASE + off - PREFIX, v, targets[v], off))
(OUT / "menu_absolute_pointers.txt").write_text(
    "\n".join(f"pointer_va=0x{p:08X} file_off=0x{o:X} -> 0x{v:08X} {s}"
              for p, v, s, o in pointer_rows) + "\n"
)

# Scan aligned instruction candidates in both ARM and Thumb modes. A match is
# still only a candidate: literal pools and embedded data can resemble code.
refs = []
for mode_name, mode, step in [
    ("THUMB", CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN, 2),
    ("ARM", CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN, 4),
]:
    md = Cs(CS_ARCH_ARM, mode)
    md.detail = True
    for rel in range(0, len(payload) - 4, step):
        va = BASE + rel
        ins = next(md.disasm(payload[rel:rel+4], va, count=1), None)
        if not ins:
            continue
        dst = None
        if ins.mnemonic.startswith("ldr") and len(ins.operands) >= 2:
            op = ins.operands[1]
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                pc = ((va + (4 if mode_name == "THUMB" else 8)) & (~3 if mode_name == "THUMB" else 0xFFFFFFFF))
                dst = (pc + op.mem.disp) & 0xFFFFFFFF
        elif ins.mnemonic == "adr" and len(ins.operands) >= 2:
            op = ins.operands[1]
            if op.type == ARM_OP_IMM:
                dst = op.imm & 0xFFFFFFFF
        if dst in targets:
            refs.append((mode_name, va, dst, ins.mnemonic, ins.op_str, ins.bytes.hex()))

(OUT / "menu_instruction_xrefs.txt").write_text(
    "\n".join(f"{m} site=0x{site:08X} target=0x{dst:08X} {mn} {op} bytes={b} => {targets[dst]}"
              for m, site, dst, mn, op, b in refs)
    or "No direct ARM/Thumb literal or ADR references found.\n"
)

# Show raw bytes and independent ARM/Thumb disassembly around the menu strings.
# This is deliberately a data/code context view, not a claimed function body.
contexts = []
for va, off, s in string_rows:
    if va is None:
        continue
    rel = va - BASE
    lo, hi = max(0, rel - 0x180), min(len(payload), rel + 0x100)
    contexts.append(f"\n===== {s} @ 0x{va:08X} | payload window 0x{lo:X}-0x{hi:X} =====")
    contexts.append("RAW HEX:")
    for p in range(lo, hi, 16):
        chunk = payload[p:min(p+16, hi)]
        contexts.append(f"{BASE+p:08X}: {chunk.hex(' ')}")
    for mode_name, mode, step in [
        ("THUMB", CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN, 2),
        ("ARM", CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN, 4),
    ]:
        md = Cs(CS_ARCH_ARM, mode)
        contexts.append(f"-- {mode_name} candidate decode --")
        start = lo - (lo % step)
        for ins in md.disasm(payload[start:hi], BASE + start):
            marker = " <STRING>" if ins.address == va else ""
            contexts.append(f"0x{ins.address:08X}: {ins.mnemonic:8} {ins.op_str} [{ins.bytes.hex()}]{marker}")
(OUT / "menu_region_context.txt").write_text("\n".join(contexts) + "\n")

summary = [
    "Oppo A15 LK menu/unlock deep inspection (READ ONLY)",
    f"image={IMAGE}", f"size={len(blob)}", f"sha256={sha}",
    f"load_base=0x{BASE:08X}", f"payload_offset=0x{PREFIX:X}",
    f"found_menu_strings={sum(1 for x in string_rows if x[0] is not None)}",
    f"absolute_pointer_hits={len(pointer_rows)}",
    f"ARM_or_THUMB_literal_ADR_xrefs={len(refs)}",
    "",
    "Interpretation limits:",
    "- Instruction sweeps can decode embedded data as instructions.",
    "- A string pointer is not proof of a function boundary or call site.",
    "- No keyscan API, boot-mode dispatch, or automatic-menu condition is asserted.",
    "- No binary modification or flashable image is generated.",
]
(OUT / "SUMMARY.txt").write_text("\n".join(summary) + "\n")
print("\n".join(summary))
