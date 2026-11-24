#!/usr/bin/env python3
"""Read-only static analysis of an Oppo A15 MediaTek LK image."""
import hashlib
import os
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

image_path = Path(os.environ.get("IMAGE_PATH", "oppo-a15-signed-test.img"))
load_base = int(os.environ.get("LOAD_BASE", "0x48000000"), 0)
prefix = int(os.environ.get("PAYLOAD_OFFSET", "0x200"), 0)
out = Path("lk-analysis")
out.mkdir(exist_ok=True)

if not image_path.is_file():
    raise SystemExit(f"LK image not found: {image_path}")

data = image_path.read_bytes()
digest = hashlib.sha256(data).hexdigest()
(out / "sha256.txt").write_text(
    f"file={image_path}\nsize={len(data)} (0x{len(data):X})\n"
    f"sha256={digest}\nload_base=0x{load_base:08X}\npayload_offset=0x{prefix:X}\n"
)
if len(data) < prefix + 4:
    raise SystemExit("Image is smaller than selected payload offset.")

payload = data[prefix:]
(out / "header.bin").write_bytes(data[:prefix])

# Search printable strings relevant to environment, security, and fastboot.
rx = re.compile(rb"[\x20-\x7e]{4,}")
matches = []
for m in rx.finditer(payload):
    value = m.group().decode("ascii", "replace")
    if re.search(r"env|seccfg|lock|unlock|fastboot|security|verify|policy|spoof|bootmode|secure", value, re.I):
        matches.append((prefix + m.start(), value))
(out / "interesting_strings.txt").write_text(
    "\n".join(
        f"file_off=0x{o:X} va~=0x{load_base + o - prefix:08X}  {value}"
        for o, value in matches
    ) or "No matching printable strings found.\n"
)

known = {
    "platform_init": 0x480028B8,
    "fastboot_fail": 0x48022CE4,
    "fastboot_info": 0x48022C40,
    "fastboot_okay": 0x48022DAC,
    "fastboot_publish": 0x4802E160,
    "fastboot_register": 0x4802E064,
    "mtk_detect_key": 0x480249F0,
    "bootmode_address": 0x480B7000,
}
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True
disassembly = []
for name, va in known.items():
    off = prefix + (va - load_base)
    disassembly.append(f"\n===== {name}: VA 0x{va:08X}, file offset 0x{off:X} =====")
    if off < prefix or off >= len(data):
        disassembly.append("OUT OF IMAGE RANGE")
        continue
    start = max(prefix, off - 0x40)
    end = min(len(data), off + 0x100)
    for ins in md.disasm(data[start:end], load_base + (start - prefix)):
        mark = "  <==" if ins.address == va else ""
        disassembly.append(f"0x{ins.address:08X}: {ins.mnemonic:8} {ins.op_str}{mark}")
(out / "known_addresses_thumb.txt").write_text("\n".join(disassembly) + "\n")

# Heuristic linear sweep: useful for candidate BL/BLX targets, not proof of function boundaries.
targets = {}
for ins in md.disasm(payload, load_base):
    if ins.mnemonic in ("bl", "blx") and ins.operands:
        try:
            target = ins.operands[0].imm
        except Exception:
            continue
        targets[target] = targets.get(target, 0) + 1
(out / "thumb_call_targets.txt").write_text(
    "\n".join(
        f"0x{addr:08X} calls={count}"
        for addr, count in sorted(targets.items(), key=lambda item: (-item[1], item[0]))
    ) + "\n"
)

summary = [
    "Oppo A15 LK static analysis completed (read-only).",
    f"Image: {image_path}",
    f"Bytes: {len(data)} (0x{len(data):X})",
    f"SHA256: {digest}",
    f"Load base: 0x{load_base:08X}; payload offset: 0x{prefix:X}",
    f"Interesting strings: {len(matches)}",
    f"Candidate BL/BLX targets: {len(targets)}",
    "",
    "Linear-sweep call targets are heuristic and may include false positives.",
    "No spoof patch is generated. Validate get_env/set_env, env-init,",
    "seccfg_get_lock_state, and fastboot command dispatch before patching.",
]
(out / "README.txt").write_text("\n".join(summary) + "\n")
print("\n".join(summary))
