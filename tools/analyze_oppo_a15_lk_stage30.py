#!/usr/bin/env python3
"""Stage 30: map boot main-loop state handlers and boot action destinations. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage30"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("task_07DCC.txt",0x48007DCC,0x100),("task_07E94.txt",0x48007E94,0x100),
("task_07F44.txt",0x48007F44,0x100),("task_07EB8.txt",0x48007EB8,0x100),
("task_07D48.txt",0x48007D48,0x100),("task_073C8.txt",0x480073C8,0xA0),
("task_07F10.txt",0x48007F10,0xA0),("task_07F64.txt",0x48007F64,0xA0),
("task_07EDC.txt",0x48007EDC,0xA0),("boot_check_21548.txt",0x48021548,0x280)]
for n,va,sz in regions: save(n,[fmt(i) for i in dis(va,sz)])
targets={va:n for n,va,sz in regions}; hits={v:[] for v in targets}
for p in range(0,len(raw)-3,2):
 h1,h2=struct.unpack_from("<HH",raw,p)
 if (h1&0xF800)==0xF000 and (h2&0xD000) in (0x9000,0xD000):
  s=(h1>>10)&1; j1=(h2>>13)&1; j2=(h2>>11)&1; i1=1^(j1^s); i2=1^(j2^s)
  imm=(s<<24)|(i1<<23)|(i2<<22)|((h1&0x3ff)<<12)|((h2&0x7ff)<<1)
  if imm&(1<<24): imm-=1<<25
  site=BASE+p; dest=(site+4+imm)&0xffffffff; dest&=~1
  if dest in hits: hits[dest].append(site)
rows=[]
for d,n in targets.items():
 rows.append(f"\n{n} 0x{d:08X}: {len(hits[d])} callers")
 rows.extend(f"  0x{x:08X}" for x in hits[d][:300])
save("BOOT_TASK_CALLERS.txt",rows)
summary=["Stage 30 read-only boot main-loop state/action trace.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 30 workflow.
