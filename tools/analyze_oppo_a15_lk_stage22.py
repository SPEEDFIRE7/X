#!/usr/bin/env python3
"""Stage 22: trace event polling and boot-mode selection state producers. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage22"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("poll_053AC.txt",0x480053AC,0x180),("timer_050D0.txt",0x480050D0,0x100),
("delay_050E4.txt",0x480050E4,0x50),("mode_event_1ECF4.txt",0x4801ECF4,0x180),
("mode_event_448D0.txt",0x480448D0,0x160),("menu_A_02EB60.txt",0x4802EB60,0x140),
("menu_B_02EC84.txt",0x4802EC84,0x140),("boot_loop_03F50.txt",0x48003F50,0x240)]
for n,va,sz in regions: save(n,[fmt(i) for i in dis(va,sz)])
targets={0x480053AC:"poll_053AC",0x480050D0:"timer_050D0",0x4801ECF4:"mode_event_1ECF4",
0x480448D0:"mode_event_448D0",0x4802EB60:"menu_A",0x4802EC84:"menu_B"}
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
 rows.append(f"\n{name} 0x{d:08X}: {len(hits[d])} BL callers")
 for site in hits[d][:500]:
  rows.append(f"  0x{site:08X}")
save("EVENT_CALLERS.txt",rows)
# Search for writes to the shared menu input structure offsets 0x138/0x13c.
# This reports nearby instruction windows around halfword/word stores with these offsets.
stores=[]
for p in range(0,len(raw)-4,2):
 va=BASE+p
 ins=dis(va,4)
 if not ins: continue
 x=ins[0]
 if x.mnemonic.startswith(("str","stur")) and any(t in x.op_str for t in ("#0x138","#0x13c","#312","#316")):
  stores.append(f"\n{fmt(x)}")
  stores.extend(fmt(y) for y in dis(max(BASE,va-12),36))
save("MENU_STATE_WRITES.txt",stores[:1200])
summary=["Stage 22 read-only event poll and menu state trace.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 22 workflow.
