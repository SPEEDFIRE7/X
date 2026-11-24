#!/usr/bin/env python3
"""Stage 11: corrected-address LK control-flow inspection. READ ONLY."""
import os, struct, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

img = Path(os.getenv("IMAGE_PATH", "oppo-a15-signed-test.img"))
base = int(os.getenv("LOAD_BASE", "0x48000000"), 0)
prefix = int(os.getenv("PAYLOAD_OFFSET", "0x200"), 0)
raw = img.read_bytes()
payload = raw[prefix:]
sha = hashlib.sha256(raw).hexdigest()
out = Path("menu-trace-stage11"); out.mkdir(exist_ok=True)
expected = "b99a899639271f0494b5d4c4be05f99be54f7ecdfb5211b556895436e4803119"

def off(va): return va - base - prefix
def dump(va, size):
    p=off(va)
    if p<0 or p>=len(payload): return [f"OUTSIDE: 0x{va:08X}"]
    lines=[]
    for q in range(p,min(len(payload),p+size),16):
        b=payload[q:min(q+16,p+size)]
        lines.append(f"0x{base+prefix+q:08X}: "+" ".join(f"{x:02X}" for x in b))
    return lines

thumb=Cs(CS_ARCH_ARM, CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); thumb.detail=True
arm=Cs(CS_ARCH_ARM, CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); arm.detail=True
def dis(va,size,md):
    p=off(va)
    if p<0 or p>=len(payload): return [f"OUTSIDE: 0x{va:08X}"]
    return [f"0x{i.address:08X}: {i.mnemonic:10} {i.op_str}" for i in md.disasm(payload[p:p+size],va)]

# Ranges are selected from Stage 10's verified mapping, not old Stage 6/8 labels.
ranges = [
    ("menu_and_adjacent_thumb.txt",0x4802E7C0,0x520,thumb),
    ("menu_and_adjacent_arm.txt",0x4802E7C0,0x520,arm),
    ("flow_region_thumb.txt",0x4802E900,0x500,thumb),
    ("flow_region_arm.txt",0x4802E900,0x500,arm),
    ("input_helpers_thumb.txt",0x48004E80,0x500,thumb),
]
for name,va,size,md in ranges:
    (out/name).write_text("\n".join(dis(va,size,md))+"\n")

targets = {
    0x4802E7EC:"menu_renderer_candidate",
    0x4802E960:"unlock_flow_candidate",
    0x4802EA84:"lock_flow_candidate",
    0x480050EC:"property_accessor_candidate",
}
# Raw literal pointer scan.
ptr=[]
for va,label in targets.items():
    for v in (va,va|1):
        needle=struct.pack("<I",v); pos=0; hits=[]
        while True:
            pos=payload.find(needle,pos)
            if pos<0: break
            hits.append(base+prefix+pos); pos+=1
        ptr.append(f"{label} target=0x{va:08X} raw_pointer_hits={len(hits)}")
        for h in hits:
            ptr.append(f"  slot=0x{h:08X}")
            ptr += ["    "+x for x in dump(h-8,0x20)]
(out/"RAW_POINTERS.txt").write_text("\n".join(ptr)+"\n")

# Candidate Thumb BL scan over halfword boundaries; each hit gets surrounding instructions.
# This is a candidate list, not proof unless surrounding decode is coherent.
branches=[]
for pos in range(0,len(payload)-4,2):
    va=base+prefix+pos
    for ins in thumb.disasm(payload[pos:pos+4],va,count=1):
        if ins.mnemonic == "bl":
            try: dest=int(ins.op_str.split("#")[-1],16)
            except: continue
            if dest in targets:
                branches.append((va,dest,ins.op_str))
lines=["Candidate Thumb BL sites to tracked routines (validate surrounding function boundaries):"]
for site,dest,op in branches:
    lines.append(f"0x{site:08X} -> 0x{dest:08X} {targets[dest]} ({op})")
    lines += ["  "+x for x in dis(site-0x10,0x30,thumb)]
(out/"BL_CANDIDATES.txt").write_text("\n".join(lines)+"\n")

# Literal words surrounding menu's literal pool and function body.
literal=[]
for va in range(0x4802E820,0x4802E8A0,4):
    p=off(va)
    if 0<=p<=len(payload)-4:
        w=struct.unpack_from("<I",payload,p)[0]
        literal.append(f"0x{va:08X}: 0x{w:08X}")
(out/"MENU_LITERAL_POOL.txt").write_text("\n".join(literal)+"\n")

summary=[
"Stage 11 corrected-address inspection; read-only.",
f"image={img}",f"size={len(raw)}",f"sha256={sha}",
f"expected_sha_match={sha==expected}",
f"mapping=VA 0x{base:08X} + payload offset 0x{prefix:X}",
"Stage 10 shows menu-print sequence begins at 0x4802E7EC; Stage 11 dumps the larger adjacent and suspected flow regions.",
"Thumb BL scan is candidate-only; use coherent instruction context before accepting any caller.",
"0x480050EC is treated as property accessor candidate, not a hardware key reader.",
"No image bytes modified."
]
(out/"SUMMARY.txt").write_text("\n".join(summary)+"\n")
print((out/"SUMMARY.txt").read_text())
