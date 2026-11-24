#!/usr/bin/env python3
"""Stage 35: inspect boot state storage and its initialization/use sites. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage35"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("state_storage_89E4.txt",0x483C89E4,0x100),("boot_parent_03100.txt",0x48003100,0x280),
("boot_loop_03F50.txt",0x48003F50,0x240),("boot_check_21548.txt",0x48021548,0x280),
("boot_state_tasks_07.txt",0x48007D00,0x220)]
for n,va,sz in regions:
 if va>=BASE: save(n,[fmt(i) for i in dis(va,sz)])
# Raw words at the state location, with pointer classification.
for start,size,name in [(0x483C89E4,0x100,"STATE_WORDS.txt"),(0x483C5760,0x40,"STATE_POINTER_TABLE.txt")]:
 b=get(start,size); rows=[f"base=0x{start:08X}"]
 for p in range(0,len(b)-3,4):
  v=struct.unpack_from("<I",b,p)[0]
  rows.append(f"+0x{p:02X} 0x{start+p:08X}: 0x{v:08X}")
 save(name,rows)
# Search all aligned occurrences of the state pointer/table address and report their location.
refs=[]
for p in range(0,len(raw)-3,4):
 v=struct.unpack_from("<I",raw,p)[0]
 if v in (0x483C89E4,0x483C5760,0x4802E7EC,0x4802EB60,0x4802EC84):
  refs.append(f"file+0x{p:08X} VA=0x{BASE+p:08X}: 0x{v:08X}")
save("STATE_AND_MENU_POINTER_OCCURRENCES.txt",refs)
summary=["Stage 35 read-only boot state storage analysis.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))
