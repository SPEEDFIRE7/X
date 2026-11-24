#!/usr/bin/env python3
"""Oppo A15 LK Stage 10: inspect pointer-table context and key-input routines.
Read-only analysis. It never patches or rewrites the LK image.
"""
import os, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

IMAGE = Path(os.getenv("IMAGE_PATH", "oppo-a15-signed-test.img"))
BASE = int(os.getenv("LOAD_BASE", "0x48000000"), 0)
PREFIX = int(os.getenv("PAYLOAD_OFFSET", "0x200"), 0)
raw = IMAGE.read_bytes()
data = raw[PREFIX:]
OUT = Path("menu-trace-stage10")
OUT.mkdir(exist_ok=True)

EXPECTED_SHA = "b99a899639271f0494b5d4c4be05f99be54f7ecdfb5211b556895436e4803119"
md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md_t.detail = True
md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN); md_a.detail = True

# Stage 9 reported these pointer slots. Re-check exact values and dump surrounding data.
SLOTS = {
    0x483C53E0: ("unlock-flow pointer slot", 0x4802E961),
    0x483C5568: ("lock-flow pointer slot", 0x4802EA85),
    0x483E2754: ("key-helper pointer slot", 0x480050ED),
}
TARGETS = {
    0x4802E960: "unlock_confirmation_flow",
    0x4802EA84: "lock_confirmation_flow",
    0x4802E5EC: "boot_mode_menu_renderer",
    0x480050EC: "key_input_helper_candidate",
}
def va_off(va):
    return va - BASE - PREFIX

def hex_dump(start_va, size):
    off = va_off(start_va)
    if off < 0 or off >= len(data):
        return [f"OUT OF IMAGE: VA 0x{start_va:08X}"]
    end = min(len(data), off + size)
    out = []
    for p in range(off, end, 16):
        chunk = data[p:min(end, p+16)]
        words = " ".join(f"{b:02X}" for b in chunk)
        out.append(f"0x{BASE+PREFIX+p:08X}: {words}")
    return out

def disasm(start_va, size, mode):
    off = va_off(start_va)
    if off < 0 or off >= len(data):
        return [f"OUT OF IMAGE: VA 0x{start_va:08X}"]
    md = md_t if mode == "thumb" else md_a
    return [f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
            for i in md.disasm(data[off:min(len(data),off+size)], start_va)]

sha = hashlib.sha256(raw).hexdigest()
summary = [
    "Oppo A15 LK Stage 10 - pointer context and key input inspection (read-only)",
    f"image={IMAGE}", f"sha256={sha}", f"size={len(raw)}",
    f"payload_offset=0x{PREFIX:X} load_base=0x{BASE:08X}",
    f"expected_stage_image_sha256_match={sha == EXPECTED_SHA}",
    f"mapped_payload_va_end=0x{BASE+PREFIX+len(data):08X}",
    "",
    "POINTER SLOT VALIDATION:",
]
for slot, (label, expected) in SLOTS.items():
    off = va_off(slot)
    if off < 0 or off + 4 > len(data):
        summary.append(f"{label}: slot 0x{slot:08X} outside mapped payload")
        continue
    actual = struct.unpack_from("<I", data, off)[0]
    summary.append(f"{label}: slot=0x{slot:08X} actual=0x{actual:08X} expected=0x{expected:08X} match={actual==expected}")
    summary.append("  surrounding bytes:")
    summary.extend("  "+x for x in hex_dump(slot-0x30, 0x70))
    summary.append("  neighboring aligned words:")
    for va in range(slot-0x20, slot+0x24, 4):
        o = va_off(va)
        if 0 <= o <= len(data)-4:
            val = struct.unpack_from("<I", data, o)[0]
            summary.append(f"    0x{va:08X}: 0x{val:08X}")

# Find all exact pointer forms again, and capture local neighborhoods.
summary += ["", "ALL EXACT POINTER MATCHES:"]
for target, label in TARGETS.items():
    matches = []
    for value in (target, target | 1):
        needle = struct.pack("<I", value)
        p = 0
        while True:
            p = data.find(needle, p)
            if p < 0: break
            matches.append((BASE+PREFIX+p, value))
            p += 1
    summary.append(f"{label} target=0x{target:08X} matches={len(matches)}")
    for site, value in matches:
        summary.append(f"  slot=0x{site:08X} word=0x{value:08X}")
        summary.extend("    "+x for x in hex_dump(site-0x10, 0x30))

(OUT/"POINTER_CONTEXT.txt").write_text("\n".join(summary)+"\n")

# Produce both ARM and Thumb decodes because ISA state is not yet proven at every entry.
files = {
    "key_helper_thumb.txt": disasm(0x480050A0, 0x260, "thumb"),
    "key_helper_arm.txt": disasm(0x480050A0, 0x260, "arm"),
    "menu_unlock_thumb.txt": disasm(0x4802E5A0, 0x300, "thumb"),
    "menu_unlock_arm.txt": disasm(0x4802E5A0, 0x300, "arm"),
}
for name, lines in files.items():
    (OUT/name).write_text("\n".join(lines)+"\n")

# Scan for aligned literal values in the mapped payload, recording offsets and context.
# This is data evidence only; it does not establish a code xref.
literal_lines = ["Pointer/value occurrence scan (raw bytes; not proof of code reference)"]
for target, label in TARGETS.items():
    for value in (target, target | 1):
        needle = struct.pack("<I", value)
        p = 0
        while True:
            p = data.find(needle, p)
            if p < 0: break
            va = BASE + PREFIX + p
            literal_lines.append(f"{label}: value=0x{value:08X} at 0x{va:08X}")
            p += 1
(OUT/"RAW_POINTER_OCCURRENCES.txt").write_text("\n".join(literal_lines)+"\n")

final = [
    "Stage 10 completed as read-only inspection.",
    f"image_sha256={sha}",
    f"expected_image_match={sha == EXPECTED_SHA}",
    "Review POINTER_CONTEXT.txt for pointer slot contents and adjacent words.",
    "Review key_helper_thumb.txt and key_helper_arm.txt side-by-side; do not assign key semantics unless control flow and callers support it.",
    "A pointer slot alone does not prove a function table or invocation path.",
    "No LK image bytes modified.",
]
(OUT/"SUMMARY.txt").write_text("\n".join(final)+"\n")
print((OUT/"SUMMARY.txt").read_text())
