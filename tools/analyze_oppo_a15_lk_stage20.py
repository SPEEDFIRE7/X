#!/usr/bin/env python3
"""Stage 20: inspect LK low-level input read/write primitives and callers. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage20"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("lowlevel_06000.txt",0x48006000,0x400),("lowlevel_0610C.txt",0x480060D0,0x180),
("lowlevel_0611C.txt",0x4800611C,0x100),("key_wrapper_06D44.txt",0x48006D44,0xA0),
("key_wrapper_06D8C.txt",0x48006D8C,0x90),("key_wrapper_06DFC.txt",0x48006DFC,0x60),
("keycheck_A_06F5C.txt",0x48006F5C,0x50),("keycheck_B_06FA0.txt",0x48006FA0,0x50)]
for n,va,sz in regions: save(n,[fmt(i) for i in dis(va,sz)])
targets={0x4800610C:"lowlevel_read_0610C",0x4800611C:"lowlevel_write_0611C",
0x48006D44:"read_wrapper_06D44",0x48006D8C:"read_wrapper_06D8C",0x48006DFC:"read_wrapper_06DFC"}
hits={k:[] for k in targets}
for p in range(0,len(raw)-3,2):
 h1,h2=struct.unpack_from("<HH",raw,p)
 if (h1&0xF800)==0xF000 and (h2&0xD000)==0xD000:
  s=(h1>>10)&1; j1=(h2>>13)&1; j2=(h2>>11)&1; i1=1^(j1^s); i2=1^(j2^s)
  imm=(s<<24)|(i1<<23)|(i2<<22)|((h1&0x3ff)<<12)|((h2&0x7ff)<<1)
  if imm&(1<<24): imm-=1<<25
  site=BASE+p; dest=(site+4+imm)&0xffffffff; dest&=~1
  if dest in hits: hits[dest].append(site)
rows=[]
for d,name in targets.items():
 rows.append(f"\n{name} 0x{d:08X}: {len(hits[d])} direct BL candidates")
 for site in hits[d]:
  rows.append(f"  caller 0x{site:08X}")
  rows.extend(fmt(i) for i in dis(site-16,56))
save("LOWLEVEL_CALLERS.txt",rows)
# Print byte values and decoded instructions around potential hardware registers and constants.
const=[]
for p in range(0,len(raw)-3,4):
 v=struct.unpack_from("<I",raw,p)[0]
 if v in (0x10007000,0x10006000,0x10005000,0x10000000,0x11002000,0x11003000,0x10010000):
  const.append(f"file+0x{p:X} VA=0x{BASE+p:08X}: 0x{v:08X}")
save("MMIO_CONSTANTS.txt",const)
summary=["Stage 20 read-only low-level input primitive analysis.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 20 workflow.
