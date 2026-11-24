#!/usr/bin/env python3
"""Stage 19: inspect low-level key-state routine and its callees. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage19"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("key_api_06D00.txt",0x48006D00,0x180),("key_helper_06DFC.txt",0x48006DD0,0x100),
("key_helper_06E38.txt",0x48006E10,0x100),("key_check_A_06F5C.txt",0x48006F5C,0x50),
("key_check_B_06FA0.txt",0x48006FA0,0x50),("key_dispatch_052EC.txt",0x480052EC,0x80)]
for n,va,sz in regions: save(n,[fmt(i) for i in dis(va,sz)])
# Scan BL calls to known low-level helpers and collect surrounding code in key-related windows.
targets={0x48006D44:"key_state_api",0x48006DFC:"key_helper_DFC",0x48006E38:"key_helper_E38",
0x48006F04:"key_helper_F04",0x48006FA0:"key_check_B",0x48006F5C:"key_check_A"}
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
for d,n in targets.items():
 rows.append(f"\n{n} 0x{d:08X}: {len(hits[d])} candidates")
 for site in hits[d]:
  if 0x48006C00<=site<=0x48007100 or 0x48005200<=site<=0x48005400:
   rows.append(f"  caller 0x{site:08X}"); rows.extend(fmt(i) for i in dis(site-12,40))
save("KEY_API_CALLERS.txt",rows)
summary=["Stage 19 read-only key-state API inspection.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 19 workflow.
