#!/usr/bin/env python3
"""Read-only reboot/menu reconnaissance for the Oppo A15 MTK LK image.

This is triage only: string references are not proof of function boundaries.
No patch or modified image is produced.
"""
import hashlib, os, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

IMAGE = Path(os.environ.get("IMAGE_PATH", "oppo-a15-signed-test.img"))
BASE = int(os.environ.get("LOAD_BASE", "0x48000000"), 0)
PREFIX = int(os.environ.get("PAYLOAD_OFFSET", "0x200"), 0)
OUT = Path("reboot-analysis")
OUT.mkdir(exist_ok=True)
if not IMAGE.is_file():
    raise SystemExit(f"LK image not found: {IMAGE}")
blob = IMAGE.read_bytes()
if len(blob) < PREFIX + 4:
    raise SystemExit("Invalid payload offset")
payload = blob[PREFIX:]
sha = hashlib.sha256(blob).hexdigest()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True

# Include key/button, boot-mode and reboot vocabulary, not only fastboot.
pat = re.compile(
    r"reboot|boot.?mode|boot.?loader|recovery|download|fastboot|"
    r"volume|power.?key|key.?press|key.?code|press.*key|"
    r"normal.?boot|rtc.?fastboot|boot.?reason|shutdown|power.?off",
    re.I,
)
strings = []
for m in re.finditer(rb"[\x20-\x7e]{4,}", payload):
    s = m.group().decode("ascii", "replace")
    if pat.search(s):
        strings.append((BASE + m.start(), PREFIX + m.start(), s))

# Collect direct PC-relative references to target strings from halfword-aligned
# Thumb decoding. This is deliberately labelled candidate-only.
targets = {va: (off, s) for va, off, s in strings}
xrefs = []
for rel in range(0, len(payload) - 4, 2):
    va = BASE + rel
    ins_list = list(md.disasm(payload[rel:rel+4], va, count=1))
    if not ins_list:
        continue
    ins = ins_list[0]
    target = None
    if ins.mnemonic.startswith("ldr") and len(ins.operands) >= 2:
        op = ins.operands[1]
        if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
            target = ((va + 4) & ~3) + op.mem.disp
    elif ins.mnemonic == "adr" and len(ins.operands) >= 2:
        op = ins.operands[1]
        if op.type == ARM_OP_IMM:
            target = op.imm & 0xffffffff
    if target in targets:
        off, s = targets[target]
        xrefs.append((va, target, ins.mnemonic, ins.op_str, s))

(OUT / "reboot_strings.txt").write_text(
    "\n".join(f"va=0x{va:08X} file_off=0x{off:X} {s}" for va, off, s in strings) + "\n"
)
(OUT / "reboot_string_xrefs.txt").write_text(
    "\n".join(f"site=0x{site:08X} target=0x{target:08X} {mn} {op} => {s}"
              for site, target, mn, op, s in xrefs)
    or "No direct PC-relative xrefs found; this does not mean the strings are unused.\n"
)

# Disassembly context for each xref, including preceding bytes that may contain
# a prologue. The report does not claim that the window start is a function.
contexts = []
seen = set()
for site, target, mn, op, s in xrefs:
    start = max(0, site - BASE - 0x60) & ~1
    if start in seen:
        continue
    seen.add(start)
    end = min(len(payload), site - BASE + 0x90)
    contexts.append(f"\n===== xref site 0x{site:08X} -> 0x{target:08X}: {s} =====")
    for ins in md.disasm(payload[start:end], BASE + start):
        marker = " <== xref" if ins.address == site else ""
        contexts.append(f"0x{ins.address:08X}: {ins.mnemonic:8} {ins.op_str} [{ins.bytes.hex()}]{marker}")
(OUT / "reboot_xref_context.txt").write_text("\n".join(contexts) + "\n")

# Aligned absolute pointers to strings can reveal data tables/callback arrays.
ptrs = []
for pos in range(PREFIX, len(blob) - 3, 4):
    value = struct.unpack_from("<I", blob, pos)[0]
    if value in targets:
        off, s = targets[value]
        ptrs.append(f"pointer_file_off=0x{pos:X} pointer_va=0x{BASE+pos-PREFIX:08X} target=0x{value:08X} {s}")
(OUT / "reboot_string_pointers.txt").write_text("\n".join(ptrs) + ("\n" if ptrs else "No aligned absolute pointers found.\n"))

header_magic = struct.unpack_from("<I", blob, 0)[0]
header_size = struct.unpack_from("<I", blob, 4)[0]
summary = [
    "Oppo A15 LK reboot/menu reconnaissance (READ ONLY)",
    f"image={IMAGE}", f"size={len(blob)}", f"sha256={sha}",
    f"load_base=0x{BASE:08X}", f"payload_offset=0x{PREFIX:X}",
    f"header_magic=0x{header_magic:08X}", f"header_payload_size=0x{header_size:X}",
    f"actual_payload_size=0x{len(payload):X}",
    f"candidate_reboot_strings={len(strings)}", f"candidate_string_xrefs={len(xrefs)}",
    f"aligned_string_pointers={len(ptrs)}",
    "",
    "CAVEATS:",
    "- Halfword-aligned Thumb decoding can decode data as instructions.",
    "- String references are candidate locations, not verified function starts.",
    "- This pass does not identify GPIO/keyscan APIs or prove reboot-mode values.",
    "- No binary patch is produced; do not flash any analysis artifact.",
]
(OUT / "SUMMARY.txt").write_text("\n".join(summary) + "\n")
print("\n".join(summary))
