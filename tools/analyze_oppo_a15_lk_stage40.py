#!/usr/bin/env python3
"""Stage 40: correct Thumb PC semantics and inspect the two distinct global bases. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage40"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(a,n):
 p=a-BASE
 return raw[p:p+n] if 0<=p and p+n<=len(raw) else b""
def dis(a,n): return list(md.disasm(get(a,n),a))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
def dump(a,n):
 b=get(a,n); z=[f"base=0x{a:08X} size=0x{len(b):X}"]
 for o in range(0,len(b)-3,4): z.append(f"+0x{o:03X} @0x{a+o:08X}: 0x{struct.unpack_from('<I',b,o)[0]:08X}")
 return z
sha=hashlib.sha256(raw).hexdigest()
save("IMAGE_ID.txt",[f"size={len(raw)}",f"sha256={sha}","READ ONLY"])
# ADD Rd,PC uses the Thumb PC value address+4 here (not the aligned LDR-literal base).
parent_base=0x48002FA2+4+0x003C2376
main_base=0x48003F58+4+0x003C13C0
save("CORRECT_GLOBAL_BASES.txt",[
 f"parent r5: 0x48002FA2 ADD r5,PC -> 0x48002FA6 + 0x003C2376 = 0x{parent_base:08X}",
 f"main r4: 0x48003F58 ADD r4,PC -> 0x48003F5C + 0x003C13C0 = 0x{main_base:08X}",
 "These are distinct bases in distinct functions."
])
# Parent table: offsets used after main loop.
for name,off,n in [
 ("parent_slot_444.txt",0x444,0x80),
 ("parent_slot_514.txt",0x514,0x80),
 ("parent_slot_590.txt",0x590,0x40),
 ("parent_base_region.txt",0,0x600),
]:
 save(name,dump(parent_base+off,n))
# Main-loop table slots, including apparent code pointer at +0x444.
for name,off,n in [
 ("main_slot_2D8.txt",0x2D8,0x40),
 ("main_slot_444.txt",0x444,0x40),
 ("main_slot_4C0.txt",0x4C0,0x40),
 ("main_slot_514.txt",0x514,0x40),
]:
 save(name,dump(main_base+off,n))
# Inspect the pointed address from main +0x444 and nearby bytes/code.
v=struct.unpack("<I",get(main_base+0x444,4))[0]
ptr=v & ~1
save("main_444_target_bytes.txt",dump(ptr-0x20,0x100) if BASE<=ptr-0x20<BASE+len(raw) else ["target outside image"])
save("main_444_target_disasm.txt",[fmt(i) for i in dis(ptr-0x20,0x100)] if BASE<=ptr-0x20<BASE+len(raw) else ["target outside image"])
# Check whether parent table entry at +444 points to the DT-like block and show the first fields.
pv=struct.unpack("<I",get(parent_base+0x444,4))[0]
save("parent_444_target.txt",[
 f"parent table slot=0x{parent_base+0x444:08X}",
 f"slot value=0x{pv:08X}",
 f"target first words:",
 *dump(pv,0x80)
])
save("SUMMARY.txt",[
 "Stage 40 corrected Thumb PC calculations and separated parent/main global bases.",
 f"sha256={sha}",f"parent_r5_base=0x{parent_base:08X}",f"main_r4_base=0x{main_base:08X}",
 "Parent +0x444 and main-loop +0x444 are different slots; do not conflate them.",
 "No LK image bytes modified."
])
print("\n".join(["Stage 40 complete",f"sha256={sha}",f"parent_r5_base=0x{parent_base:08X}",f"main_r4_base=0x{main_base:08X}"]))
