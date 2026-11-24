#!/usr/bin/env python3
"""Stage 13: resolve key dispatcher and menu entry paths. READ ONLY."""
import os, struct, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

img = Path(os.getenv("IMAGE_PATH", "oppo-a15-signed-test.img"))
base = int(os.getenv("LOAD_BASE", "0x48000000"), 0)
prefix = int(os.getenv("PAYLOAD_OFFSET", "0x200"), 0)
raw = img.read_bytes()
payload = raw[prefix:]
sha = hashlib.sha256(raw).hexdigest()
expected = "b99a899639271f0494b5d4c4be05f99be54f7ecdfb5211b556895436e4803119"
out = Path("menu-trace-stage13"); out.mkdir(exist_ok=True)

thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); thumb.detail = True
arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN); arm.detail = True

def off(va): return va - base - prefix
def bytes_at(va,n):
    p=off(va)
    if p<0 or p+n>len(payload): return b""
    return payload[p:p+n]
def dump(va,n):
    b=bytes_at(va,n); lines=[]
    for j in range(0,len(b),16):
        lines.append(f"0x{va+j:08X}: "+" ".join(f"{x:02X}" for x in b[j:j+16]))
    return lines
def dis(va,n,md):
    b=bytes_at(va,n)
    return [f"0x{i.address:08X}: {i.mnemonic:10} {i.op_str}" for i in md.disasm(b,va)]
def write(name,lines): (out/name).write_text("\n".join(lines)+"\n")

# Stage 12 call sites show this code consumes a 16-bit value and tests its result.
# Decode exact dispatcher area at several halfword offsets; do not assume a function boundary.
for name,va,n in [
 ("dispatcher_05200_thumb.txt",0x48005200,0x300),
 ("dispatcher_05280_thumb.txt",0x48005280,0x240),
 ("dispatcher_052EC_thumb.txt",0x480052EC,0x180),
 ("caller_04000_thumb.txt",0x48003F80,0x280),
 ("caller_04000_arm.txt",0x48003F80,0x280),
 ("menu_entry_02E900_thumb.txt",0x4802E900,0x380),
 ("menu_entry_02E900_arm.txt",0x4802E900,0x380),
 ("menu_helpers_02E800_thumb.txt",0x4802E800,0x180),
]:
    md = arm if name.endswith("_arm.txt") else thumb
    write(name, dis(va,n,md))

# Raw bytes around candidate dispatcher and callers; these also reveal whether
# the earlier empty Capstone dump was caused by mapping or instruction alignment.
write("RAW_KEY_AND_CALLER_BYTES.txt",
      ["--- 0x480051C0..0x48005480 ---", *dump(0x480051C0,0x2C0),
       "--- 0x48003F80..0x48004200 ---", *dump(0x48003F80,0x280)])

# Search a bounded window before 0x052EC for common Thumb function prologues.
# Results are candidates only; surrounding control flow must validate them.
b=bytes_at(0x48004E00,0x600)
pro=[]
for i in range(0,len(b)-2,2):
    h=struct.unpack_from("<H",b,i)[0]
    # PUSH with LR saved, including common register masks.
    if (h & 0xFE00) == 0xB400 and (h & 0x0100):
        pro.append(f"0x{0x48004E00+i:08X}: PUSH 0x{h:04X}")
write("THUMB_PROLOGUE_CANDIDATES.txt",pro or ["No common PUSH/LR prologues found in scan window."])

# Literal words and absolute pointer references to the candidate key routine.
literal=[]
for va in range(0x480052A0,0x480053C0,4):
    x=bytes_at(va,4)
    if len(x)==4: literal.append(f"0x{va:08X}: 0x{struct.unpack('<I',x)[0]:08X}")
write("DISPATCHER_LITERAL_WORDS.txt",literal)

target=0x480052EC
hits=[]
for p in range(0,len(payload)-3,2):
    w=struct.unpack_from("<I",payload,p)[0]
    if w in (target,target|1):
        hits.append(f"0x{base+prefix+p:08X}: 0x{w:08X}")
write("RAW_POINTERS_TO_052EC.txt",hits or ["No aligned raw pointer occurrences."])

summary=[
"Stage 13 read-only dispatcher and entry-path analysis.",
f"image={img}",f"size={len(raw)}",f"sha256={sha}",f"expected_sha_match={sha==expected}",
f"payload_offset=0x{prefix:X}; load_base=0x{base:08X}",
"Stage 12 established coherent Thumb callers at 0x480040D2 and 0x4800413E/0x48004150, plus menu loops at 0x4802EB60 and 0x4802EC84.",
"Stage 13 emits raw bytes and overlapping Thumb/ARM disassemblies around 0x480052EC to resolve why the Stage 12 dispatcher dump was empty.",
"Prologue and pointer scans are candidates only, not proof of function boundaries or automatic invocation.",
"No LK image bytes modified."
]
write("SUMMARY.txt",summary)
print("\n".join(summary))
