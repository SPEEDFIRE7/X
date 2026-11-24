#!/usr/bin/env python3
"""Stage 21: inspect shared LK property/IO dispatcher behind key reads. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage21"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("dispatcher_05618.txt",0x48005580,0x240),("io_05500.txt",0x48005500,0x180),
("key_wrapper_0610C.txt",0x4800610C,0x30),("config_0512C.txt",0x4800512C,0x90),
("main_loop_03F50.txt",0x48003F50,0x220),("key_use_06D44.txt",0x48006D44,0xA0),
("key_use_07644.txt",0x48007644,0x1A0)]
for n,va,sz in regions: save(n,[fmt(i) for i in dis(va,sz)])
targets={0x48005618:"io_dispatch_05618",0x4800610C:"read_wrapper_0610C",0x4800611C:"write_wrapper_0611C",
0x480050D0:"timer_helper_050D0",0x480052EC:"keycode_validator_052EC"}
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
 rows.append(f"\n{name} 0x{d:08X}: {len(hits[d])} calls")
 for site in hits[d][:300]: rows.append(f"  0x{site:08X}")
save("DISPATCH_CALLERS.txt",rows)
# Extract all immediate key-like request IDs used by wrappers in region 06D00-07840.
ids=[]
for va in range(0x48006D00,0x48007840,2):
 ins=dis(va,4)
 if ins and ins[0].mnemonic in ("movw","movs","mov.w"):
  op=ins[0].op_str
  if op.startswith("r0,") or op.startswith("r1,"):
   ids.append(f"0x{va:08X}: {ins[0].mnemonic} {op}")
save("IO_REQUEST_IDS.txt",ids)
summary=["Stage 21 read-only shared IO dispatcher analysis.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))
