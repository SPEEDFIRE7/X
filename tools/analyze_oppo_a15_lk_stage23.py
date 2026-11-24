#!/usr/bin/env python3
"""Stage 23: trace menu entry/setup helpers and indirect dispatch sites. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage23"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("menu_helper_2E844.txt",0x4802E844,0x100),("menu_helper_2E8BC.txt",0x4802E8BC,0x100),
("menu_setup_A_2E920.txt",0x4802E920,0xA0),("menu_setup_B_2E9B4.txt",0x4802E9B4,0xA0),
("key_config_06F3C.txt",0x48006F3C,0xC0),("event_218A0.txt",0x480218A0,0x100),
("menu_indirect_region.txt",0x4802E700,0x240),("boot_dispatch_region.txt",0x48003F40,0x240)]
for n,va,sz in regions: save(n,[fmt(i) for i in dis(va,sz)])
# Collect all BLX/BX register indirect sites in executable ranges, and show context.
ind=[]
for start,end in [(0x48000000,0x48010000),(0x48020000,0x48031000),(0x48043000,0x48046000)]:
 for x in dis(start,end-start):
  if x.mnemonic in ("blx","bx") and x.op_str and not x.op_str.startswith("#"):
   ind.append(f"\n{fmt(x)}")
   ind.extend(fmt(y) for y in dis(max(BASE,x.address-12),40))
save("INDIRECT_BRANCH_SITES.txt",ind[:3000])
# Find direct BL references to setup/helper candidates.
targets={0x4802E844:"helper_2E844",0x4802E8BC:"helper_2E8BC",0x4802E920:"setup_A",0x4802E9B4:"setup_B",
0x48006F3C:"key_config_06F3C",0x480218A0:"event_218A0"}
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
 rows.append(f"\n{n} 0x{d:08X}: {len(hits[d])}")
 rows.extend(f"  0x{x:08X}" for x in hits[d][:500])
save("HELPER_CALLERS.txt",rows)
summary=["Stage 23 read-only menu entry and indirect-dispatch analysis.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 23 workflow.
