#!/usr/bin/env python3
"""Stage 24: scan Thumb direct B.W and BL branches to locate hidden menu dispatch. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage24"); OUT.mkdir(exist_ok=True)
targets={0x4802EB60:"menu_A",0x4802EC84:"menu_B",0x4802E7EC:"renderer",
0x4802E920:"setup_A",0x4802E9B4:"setup_B",0x48003F50:"boot_loop",
0x480053AC:"poll",0x480052EC:"validator",0x4802EA30:"menu_subflow"}
hits={k:[] for k in targets}; nearby=[]
def sx(v,b): return v-(1<<b) if v&(1<<(b-1)) else v
for p in range(0,len(raw)-3,2):
 h1,h2=struct.unpack_from("<HH",raw,p)
 # Thumb-2 B.W (T4) and BL (T1)
 if (h1&0xF800)==0xF000 and (h2&0xD000) in (0x9000,0xD000):
  s=(h1>>10)&1; j1=(h2>>13)&1; j2=(h2>>11)&1
  i1=1^(j1^s); i2=1^(j2^s)
  imm=(s<<24)|(i1<<23)|(i2<<22)|((h1&0x3ff)<<12)|((h2&0x7ff)<<1)
  imm=sx(imm,25); site=BASE+p; dest=(site+4+imm)&0xffffffff; dest &= ~1
  kind="BL" if (h2&0xD000)==0xD000 else "B.W"
  if dest in hits: hits[dest].append((site,kind))
  if 0x4802E700<=site<0x4802EF00 and 0x4802E700<=dest<0x4802EF00:
   nearby.append(f"0x{site:08X} {kind} -> 0x{dest:08X}")
rows=[]
for d,n in targets.items():
 rows.append(f"\n{n} 0x{d:08X}: {len(hits[d])} branch/call candidates")
 rows.extend(f"  0x{s:08X} {k}" for s,k in hits[d])
(OUT/"BRANCH_XREFS.txt").write_text("\n".join(rows)+"\n")
(OUT/"MENU_INTERNAL_BRANCHES.txt").write_text("\n".join(nearby)+"\n")
summary=["Stage 24 read-only Thumb B.W/BL xref scan.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
(OUT/"SUMMARY.txt").write_text("\n".join(summary)+"\n"); print("\n".join(summary))

# Trigger Stage 24 workflow.
