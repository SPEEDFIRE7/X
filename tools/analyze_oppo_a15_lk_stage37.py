#!/usr/bin/env python3
"""Stage 37: resolve callback literals and parent state branches. READ ONLY."""
import os, struct, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage37"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def get(va,n):
 p=va-BASE
 return raw[p:p+n] if 0<=p and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
def words(va,n):
 b=get(va,n); out=[f"base=0x{va:08X} size=0x{len(b):X}"]
 for o in range(0,len(b)-3,4):
  v=struct.unpack_from("<I",b,o)[0]
  out.append(f"+0x{o:03X} @0x{va+o:08X}: 0x{v:08X}")
 return out
sha=hashlib.sha256(raw).hexdigest()
save("IMAGE_ID.txt",[f"size={len(raw)}",f"sha256={sha}","READ ONLY"])
# Literal pools adjacent to 1B040 and 1B028; also state parent branch targets.
for name,va,n in [
 ("callback_literal_pool_1B130.txt",0x4801B130,0x60),
 ("callback_init_00300.txt",0x480002F0,0x90),
 ("parent_state_branch_3320_35C0.txt",0x48003320,0x2A0),
 ("main_loop_literal_pool_4180.txt",0x48004180,0x100),
 ("global_table_483C531C.txt",0x483C531C,0x40),
 ("callback_table_slot_483C57DC.txt",0x483C57DC,0x40),
]: save(name,words(va,n))
regions=[
 ("callback_dispatch_1AD00_1B300.txt",0x4801AD00,0x600),
 ("callback_1B040_full.txt",0x4801B040,0x220),
 ("callback_target_611A8.txt",0x480611A8,0x180),
 ("callback_init_0034C.txt",0x4800034C,0x180),
 ("parent_state_branch_3300_35D0.txt",0x48003300,0x2D0),
 ("power_reboot_core_7A600_7B000.txt",0x4807A600,0xA00),
 ("power_reboot_core_82000_82F00.txt",0x48082000,0xF00),
]
for name,va,n in regions: save(name,[fmt(i) for i in dis(va,n)])
# Search decoded instructions for direct calls/branches to candidate functions.
targets={0x4801B040,0x4801AD54,0x480611A8,0x4800034C,0x4801B028,0x4802E7EC}
hits=[]
for start,end in [(BASE+0x200,BASE+0x30000),(BASE+0x30000,BASE+0x70000)]:
 for ins in md.disasm(get(start,end-start),start):
  if ins.mnemonic.startswith(("bl","b")):
   for t in targets:
    if f"0x{t:08x}" in ins.op_str.lower():
     hits.append(f"{fmt(ins)} -> 0x{t:08X}")
save("CALL_XREFS.txt",hits)
# Locate action strings with nearby references not presumed as executable code.
needles=[b"Power Off",b"Reboot Os",b"reboot-recovery",b"reboot-fastboot",b"boot-recovery",b"boot-fastboot",b"Normal Boot"]
ss=[]
for needle in needles:
 p=0
 while True:
  p=raw.find(needle,p)
  if p<0: break
  ss.append(f"0x{BASE+p:08X} file+0x{p:X}: {raw[p:p+len(needle)+1]!r}")
  p+=1
save("ACTION_STRING_LOCATIONS.txt",ss)
save("SUMMARY.txt",[
 "Stage 37 read-only callback/state dispatch analysis.",
 f"image_size={len(raw)}",f"sha256={sha}",
 "Inspected literal pools for callback 0x4801B040 and the parent branches for state values.",
 "Callback target and external RAM object are not assigned a reboot meaning without proof.",
 "No LK image bytes modified."
])
print("\n".join(["Stage 37 complete",f"size={len(raw)}",f"sha256={sha}"]))
