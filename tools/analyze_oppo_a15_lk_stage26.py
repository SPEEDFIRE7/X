#!/usr/bin/env python3
"""Stage 26: inspect boot-mode choice handlers and their callers. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage26"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
targets=[("handler_26FBC.txt",0x48026FBC,0x120),("handler_27018.txt",0x48027018,0x120),
("handler_271E4.txt",0x480271E4,0x120),("handler_27000.txt",0x48027000,0x80),
("prompt_64F24.txt",0x48064F24,0xC0),("prompt_64F9C.txt",0x48064F9C,0xA0),
("prompt_64298.txt",0x48064298,0xC0),("prompt_26320.txt",0x48026320,0xA0),
("menu_flow_2EB60.txt",0x4802EB60,0x110),("menu_flow_2EC84.txt",0x4802EC84,0x110)]
for n,va,sz in targets: save(n,[fmt(i) for i in dis(va,sz)])
# Direct BL and B.W xrefs to handlers.
wanted={va:n for n,va,sz in targets}; hits={v:[] for v in wanted}
for p in range(0,len(raw)-3,2):
 h1,h2=struct.unpack_from("<HH",raw,p)
 if (h1&0xF800)==0xF000 and (h2&0xD000) in (0x9000,0xD000):
  s=(h1>>10)&1; j1=(h2>>13)&1; j2=(h2>>11)&1; i1=1^(j1^s); i2=1^(j2^s)
  imm=(s<<24)|(i1<<23)|(i2<<22)|((h1&0x3ff)<<12)|((h2&0x7ff)<<1)
  if imm&(1<<24): imm-=1<<25
  site=BASE+p; dest=(site+4+imm)&0xffffffff; dest&=~1
  if dest in hits: hits[dest].append((site,"BL" if (h2&0xD000)==0xD000 else "B.W"))
rows=[]
for d,name in wanted.items():
 rows.append(f"\n{name} 0x{d:08X}: {len(hits[d])}")
 rows.extend(f"  0x{s:08X} {k}" for s,k in hits[d])
save("HANDLER_XREFS.txt",rows)
summary=["Stage 26 read-only boot-mode action handler analysis.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 26 workflow.
