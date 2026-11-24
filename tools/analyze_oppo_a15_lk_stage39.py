#!/usr/bin/env python3
"""Stage 39: resolve parent r5 global base and all state-object offsets. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage39"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def get(a,n):
 p=a-BASE
 return raw[p:p+n] if 0<=p and p+n<=len(raw) else b""
def dis(a,n): return list(md.disasm(get(a,n),a))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
def w(a):
 b=get(a,4)
 return struct.unpack("<I",b)[0] if len(b)==4 else None
sha=hashlib.sha256(raw).hexdigest()
save("IMAGE_ID.txt",[f"size={len(raw)}",f"sha256={sha}","READ ONLY"])
# Decode parent prologue + state dispatcher with all PC-relative literal operands annotated.
regions=[("parent_setup_02F88_031A0.txt",0x48002F88,0x218),
         ("parent_dispatch_03190_03600.txt",0x48003190,0x470),
         ("parent_late_dispatch_03500_03880.txt",0x48003500,0x380)]
annot=[]
for name,a,n in regions:
 insns=dis(a,n); lines=[]
 for i in insns:
  lines.append(fmt(i))
  if i.mnemonic.startswith("ldr") and "[pc" in i.op_str:
   # parse immediate from Capstone operand detail, PC is Align(address+4,4)
   try:
    imm=next(op.mem.disp for op in i.operands if op.type==3 and op.mem.base==15)
    lit=((i.address+4)&~3)+imm
    val=w(lit)
    lines.append(f"    [PC-LITERAL] address=0x{lit:08X} value={('0x%08X'%val) if val is not None else 'OUTSIDE'}")
   except Exception: pass
 save(name,lines)
# r5 calculation from parent prologue: LDR at 0x48002F90 reads literal, then ADD r5,PC at 0x48002FA2.
lit=0x48002F94+0x938
off=w(lit)
r5base=((0x48002FA2+4)&~3)+off if off is not None else None
save("PARENT_R5_BASE.txt",[
 f"ldr literal address=0x{lit:08X}",f"literal word={('0x%08X'%off) if off is not None else 'none'}",
 f"ADD r5,PC address=0x48002FA2",f"resolved r5 base={('0x%08X'%r5base) if r5base else 'unresolved'}",
 "This is the parent function's r5 base; do not reuse the main-loop r4 base."
])
# Parent state object offsets loaded by literal pools in key blocks.
literal_sites=[0x48003918,0x48003924,0x48003930,0x48003934,0x48003940,0x4800394C,
               0x48003950,0x4800395C,0x48003964,0x48003970,0x48003978,0x48003984]
lines=[]
for a in literal_sites:
 val=w(a); lines.append(f"literal @0x{a:08X} = {('0x%08X'%val) if val is not None else 'OUTSIDE'}")
 if r5base is not None and val is not None and val<0x10000:
  addr=r5base+val
  lines.append(f"  r5+0x{val:X} => 0x{addr:08X} word={('0x%08X'%w(addr)) if w(addr) is not None else 'OUTSIDE_IMAGE'}")
save("PARENT_STATE_OFFSETS.txt",lines)
# Dump likely parent global base region around r5 if it resolves into image.
if r5base is not None and BASE<=r5base<BASE+len(raw):
 b=get(r5base,0x600); rows=[f"base=0x{r5base:08X} size=0x{len(b):X}"]
 for o in range(0,len(b)-3,4):
  v=struct.unpack_from("<I",b,o)[0]
  rows.append(f"+0x{o:03X} @0x{r5base+o:08X}: 0x{v:08X}")
 save("PARENT_GLOBAL_TABLE_DUMP.txt",rows)
else: save("PARENT_GLOBAL_TABLE_DUMP.txt",["r5 base is outside image or unresolved; cannot dump as static image data."])
save("SUMMARY.txt",[
 "Stage 39 completed: parent global-base and state offset resolution.",
 f"image_size={len(raw)}",f"sha256={sha}",
 f"parent_r5_base={('0x%08X'%r5base) if r5base else 'unresolved'}",
 "This stage distinguishes the parent r5 base from main-loop r4 base.",
 "No LK image bytes modified."
])
print("\n".join(["Stage 39 complete",f"sha256={sha}",f"parent_r5_base={('0x%08X'%r5base) if r5base else 'unresolved'}"]))

# Trigger after workflow registration.
