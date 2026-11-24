#!/usr/bin/env python3
"""Read-only Oppo A15 LK analysis: Thumb call scan and string cross-references."""
import hashlib
import os
import re
import struct
from pathlib import Path

from capstone import (
    Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN,
    CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN as ARM_LE,
)
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

IMAGE = Path(os.environ.get("IMAGE_PATH", "oppo-a15-signed-test.img"))
BASE = int(os.environ.get("LOAD_BASE", "0x48000000"), 0)
PREFIX = int(os.environ.get("PAYLOAD_OFFSET", "0x200"), 0)
OUT = Path("lk-analysis")
OUT.mkdir(exist_ok=True)

if not IMAGE.is_file():
    raise SystemExit(f"LK image not found: {IMAGE}")

blob = IMAGE.read_bytes()
if len(blob) < PREFIX + 4:
    raise SystemExit("Image is smaller than payload offset.")

# MediaTek LK header fields seen in this image.
magic = struct.unpack_from("<I", blob, 0)[0]
payload_size = struct.unpack_from("<I", blob, 4)[0]
payload = blob[PREFIX:]
sha = hashlib.sha256(blob).hexdigest()

# Validate, but do not silently change, the selected payload offset.
header_notes = [
    f"header_magic=0x{magic:08X}",
    f"header_payload_size=0x{payload_size:X}",
    f"actual_payload_size_from_offset=0x{len(payload):X}",
    f"payload_size_matches={payload_size == len(payload)}",
    f"payload_offset=0x{PREFIX:X}",
]
(OUT / "header_validation.txt").write_text("\n".join(header_notes) + "\n")
(OUT / "sha256.txt").write_text(
    f"file={IMAGE}\nsize={len(blob)} (0x{len(blob):X})\nsha256={sha}\n"
    f"load_base=0x{BASE:08X}\npayload_offset=0x{PREFIX:X}\n"
)
(OUT / "header.bin").write_bytes(blob[:PREFIX])

# Collect relevant printable strings and their runtime addresses.
string_re = re.compile(rb"[\x20-\x7e]{4,}")
keywords = re.compile(
    r"env|seccfg|lock|unlock|fastboot|security|verify|policy|"
    r"spoof|bootmode|secure|avb|orange|device",
    re.I,
)
strings = []
for m in string_re.finditer(payload):
    value = m.group().decode("ascii", "replace")
    if keywords.search(value):
        file_off = PREFIX + m.start()
        va = BASE + m.start()
        strings.append((file_off, va, value))

(OUT / "interesting_strings.txt").write_text(
    "\n".join(
        f"file_off=0x{o:X} va=0x{va:08X} {s}"
        for o, va, s in strings
    ) + "\n"
)

# Full halfword-aligned sweep. Each candidate is decoded independently so
# one invalid/data word cannot terminate analysis of the rest of the image.
thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
thumb.detail = True
call_rows = []
xref_rows = []
decoded = 0

for rel in range(0, len(payload) - 4, 2):
    va = BASE + rel
    chunk = payload[rel:rel + 4]
    insns = list(thumb.disasm(chunk, va, count=1))
    if not insns:
        continue
    ins = insns[0]
    decoded += 1

    if ins.mnemonic in ("bl", "blx") and ins.operands:
        op = ins.operands[0]
        if op.type == ARM_OP_IMM:
            call_rows.append(
                f"site=0x{ins.address:08X} target=0x{op.imm & 0xFFFFFFFF:08X} "
                f"bytes={ins.bytes.hex()} {ins.mnemonic} {ins.op_str}"
            )

    target = None
    # Thumb literal LDR: effective address is aligned PC + immediate.
    if ins.mnemonic.startswith("ldr") and len(ins.operands) >= 2:
        memop = ins.operands[1]
        if memop.type == ARM_OP_MEM and memop.mem.base == ARM_REG_PC:
            target = ((ins.address + 4) & ~3) + memop.mem.disp
    # ADR pseudo-instruction resolves to a PC-relative address.
    if ins.mnemonic == "adr" and len(ins.operands) >= 2:
        op = ins.operands[1]
        if op.type == ARM_OP_IMM:
            target = op.imm & 0xFFFFFFFF

    if target is not None:
        target &= 0xFFFFFFFF
        for so, sva, text in strings:
            if target == sva:
                xref_rows.append(
                    f"site=0x{ins.address:08X} string=0x{sva:08X} "
                    f"file_off=0x{so:X} {text}\n"
                    f"    {ins.mnemonic} {ins.op_str} bytes={ins.bytes.hex()}"
                )

(OUT / "thumb_call_sites.txt").write_text(
    "\n".join(call_rows) + ("\n" if call_rows else "No BL/BLX candidates found.\n")
)
(OUT / "thumb_string_xrefs.txt").write_text(
    "\n\n".join(xref_rows) + ("\n" if xref_rows else "No direct Thumb literal/ADR string xrefs found.\n")
)

# Also locate absolute pointers to relevant string addresses in data/literal pools.
pointer_rows = []
string_by_va = {va: (off, text) for off, va, text in strings}
for pos in range(PREFIX, len(blob) - 3, 4):
    value = struct.unpack_from("<I", blob, pos)[0]
    if value in string_by_va:
        off, text = string_by_va[value]
        pointer_rows.append(
            f"pointer_file_off=0x{pos:X} pointer_va=0x{BASE + pos - PREFIX:08X} "
            f"target=0x{value:08X} target_file_off=0x{off:X} {text}"
        )
(OUT / "string_pointer_xrefs.txt").write_text(
    "\n".join(pointer_rows) + ("\n" if pointer_rows else "No aligned absolute string pointers found.\n")
)

# Context around direct xrefs, useful for manual function-boundary review.
context_lines = []
seen = set()
for row in xref_rows:
    m = re.search(r"site=0x([0-9A-Fa-f]+)", row)
    if not m:
        continue
    site = int(m.group(1), 16)
    start_rel = max(0, site - BASE - 0x50)
    end_rel = min(len(payload), site - BASE + 0x70)
    if start_rel in seen:
        continue
    seen.add(start_rel)
    context_lines.append(f"\n===== xref context around 0x{site:08X} =====")
    start = start_rel & ~1
    for ins in thumb.disasm(payload[start:end_rel], BASE + start):
        context_lines.append(
            f"0x{ins.address:08X}: {ins.mnemonic:8} {ins.op_str} "
            f"[{ins.bytes.hex()}]"
        )
(OUT / "xref_context_thumb.txt").write_text(
    "\n".join(context_lines) + ("\n" if context_lines else "No xref contexts.\n")
)

# Known addresses from the previous device report. These are context only;
# their correctness must be confirmed against this exact image.
known = {
    "platform_init": 0x480028B8,
    "fastboot_fail": 0x48022CE4,
    "fastboot_info": 0x48022C40,
    "fastboot_okay": 0x48022DAC,
    "fastboot_publish": 0x4802E160,
    "fastboot_register": 0x4802E064,
    "mtk_detect_key": 0x480249F0,
}
lines = []
for name, va in known.items():
    rel = va - BASE
    lines.append(f"\n===== {name} VA=0x{va:08X} =====")
    if rel < 0 or rel >= len(payload):
        lines.append("OUT OF PAYLOAD RANGE")
        continue
    start = max(0, rel - 0x40) & ~1
    end = min(len(payload), rel + 0x100)
    for ins in thumb.disasm(payload[start:end], BASE + start):
        mark = " <== reported address" if ins.address == va else ""
        lines.append(
            f"0x{ins.address:08X}: {ins.mnemonic:8} {ins.op_str}{mark}"
        )
(OUT / "known_addresses_thumb.txt").write_text("\n".join(lines) + "\n")

summary = [
    "Oppo A15 LK enhanced static analysis (READ ONLY).",
    f"Image size: {len(blob)} (0x{len(blob):X})",
    f"SHA256: {sha}",
    *header_notes,
    f"Relevant strings: {len(strings)}",
    f"Decoded halfword-aligned Thumb candidates: {decoded}",
    f"Candidate BL/BLX sites: {len(call_rows)}",
    f"Direct Thumb string xrefs: {len(xref_rows)}",
    f"Aligned absolute string pointers: {len(pointer_rows)}",
    "",
    "IMPORTANT: sliding halfword decoding creates false positives.",
    "Review call sites and xrefs in context; none is proof of a function.",
    "No binary patch is produced. Do not flash this analysis output.",
]
(OUT / "README.txt").write_text("\n".join(summary) + "\n")
print("\n".join(summary))
