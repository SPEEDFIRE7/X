#!/usr/bin/env python3
"""Stage 36: trace LK runtime pointer and parent state dispatcher. READ ONLY."""
import os, struct, hashlib, re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

IMAGE = Path(os.getenv("IMAGE_PATH", "oppo-a15-signed-test.img"))
BASE = int(os.getenv("LOAD_BASE", "0x48000000"), 0)
raw = IMAGE.read_bytes()
OUT = Path("menu-trace-stage36")
OUT.mkdir(exist_ok=True)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True

def get(va, n):
    p = va - BASE
    return raw[p:p+n] if 0 <= p and p+n <= len(raw) else b""
def dis(va, n):
    return list(md.disasm(get(va, n), va))
def save(name, lines):
    (OUT/name).write_text("\n".join(lines) + "\n")
def fmt(i):
    return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"

# Reconfirm exact source image before interpreting any addresses.
digest = hashlib.sha256(raw).hexdigest()
save("IMAGE_ID.txt", [f"path={IMAGE}", f"size={len(raw)}", f"sha256={digest}",
                      f"load_base=0x{BASE:08X}", "READ ONLY: no image bytes modified."])

# Pointer table and external runtime pointer are data, not code.
for name, va, size in [
    ("pointer_table_483C5760.txt", 0x483C5760, 0x80),
    ("external_pointer_slot_483C57DC.txt", 0x483C57DC, 0x40),
    ("device_tree_blob_483C89E4.txt", 0x483C89E4, 0x100),
]:
    b = get(va, size)
    lines = [f"base=0x{va:08X} bytes={len(b)}"]
    for off in range(0, len(b)-3, 4):
        v = struct.unpack_from("<I", b, off)[0]
        lines.append(f"+0x{off:03X} @0x{va+off:08X}: 0x{v:08X}")
    save(name, lines)

# Focused disassembly of parent, main loop, and likely dispatch helpers.
regions = [
    ("parent_030F0_03680.txt", 0x480030F0, 0x590),
    ("main_loop_03F50_04250.txt", 0x48003F50, 0x300),
    ("callback_dispatch_1B000_1B100.txt", 0x4801B000, 0x120),
    ("boot_state_parser_21500_21920.txt", 0x48021500, 0x420),
    ("reboot_helpers_26E80_27240.txt", 0x48026E80, 0x3C0),
    ("key_handler_052A0_053D0.txt", 0x480052A0, 0x130),
]
for name, va, size in regions:
    save(name, [fmt(i) for i in dis(va, size)])

# Search code for literal loads / immediates mentioning relevant table and state addresses.
targets = {0x483C5760, 0x483C57DC, 0x48459CE0, 0x483C89E4,
           0x4802E7EC, 0x4802EB60, 0x4802EC84}
hits = []
# Disassemble aligned Thumb stream in bounded executable range; record exact operands only.
for start, end in [(BASE+0x200, BASE+0x90000), (BASE+0x1A000, BASE+0x2F000)]:
    start = max(start, BASE+0x200)
    end = min(end, BASE+len(raw))
    for ins in md.disasm(get(start, end-start), start):
        text = ins.op_str.lower()
        vals = re.findall(r"0x[0-9a-f]+", text)
        for token in vals:
            try: value = int(token, 16)
            except ValueError: continue
            if value in targets:
                hits.append(f"{fmt(ins)}  [target=0x{value:08X}]")
save("TARGET_OPERAND_HITS.txt", hits or ["No direct decoded operand matches; pointer may be loaded through PC-relative literal/table indirection."])

# Dump literal words in the main parent/loop neighborhood, preserving data/code distinction.
literal_lines = []
for va, size in [(0x480030F0,0x700),(0x48003F50,0x300),(0x4801B000,0x180)]:
    b = get(va,size)
    for off in range(0, len(b)-3, 4):
        v = struct.unpack_from("<I",b,off)[0]
        if v in targets or 0x48000000 <= (v & ~1) < 0x48400000 or v >= 0x48400000:
            literal_lines.append(f"region=0x{va:08X} file+0x{va-BASE+off:08X} VA=0x{va+off:08X} word=0x{v:08X}")
save("PARENT_LOOP_POINTER_WORDS.txt", literal_lines)

# Collect action-related strings and their exact virtual addresses.
needles = [b"boot-recovery", b"boot-fastboot", b"reboot", b"recovery", b"fastboot",
           b"power off", b"shutdown", b"normal boot", b"off-mode-charge"]
strings = []
for needle in needles:
    pos = 0
    while True:
        p = raw.lower().find(needle.lower(), pos)
        if p < 0: break
        sample = raw[p:p+100].split(b"\x00",1)[0]
        strings.append(f"file+0x{p:08X} VA=0x{BASE+p:08X} {sample!r}")
        pos = p + 1
save("BOOT_ACTION_STRINGS.txt", sorted(set(strings)))

summary = [
    "Stage 36 completed: read-only pointer/dispatcher trace.",
    f"image_size={len(raw)}",
    f"sha256={digest}",
    "The slot at 0x483C57DC is inspected as an in-image pointer slot.",
    "The value 0x48459CE0 is outside the LK image and cannot be dereferenced from this file alone.",
    "No assumption is made that state codes 1, 2, 3, 0x0B, or 0x63 are reboot destinations.",
    "No LK image bytes modified."
]
save("SUMMARY.txt", summary)
print("\n".join(summary))
