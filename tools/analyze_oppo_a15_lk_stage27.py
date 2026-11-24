#!/usr/bin/env python3
"""Stage 27: locate boot-mode action functions and command-string references. READ ONLY."""
import os,struct,hashlib,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage27"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("reboot_helper_0788C.txt",0x4800788C,0x180),("boot_cmds_21600.txt",0x48021580,0x220),
("generic_cmd_26F50.txt",0x48026F50,0x100),("generic_cmd_26EB4.txt",0x48026EB4,0x120),
("boot_mode_renderer_2E7EC.txt",0x4802E7EC,0x100),("unlock_menu_2EB60.txt",0x4802EB60,0x110),
("lock_menu_2EC84.txt",0x4802EC84,0x110),("boot_loop_03F50.txt",0x48003F50,0x240)]
for n,va,sz in regions: save(n,[fmt(i) for i in dis(va,sz)])
# Search literal LDR + ADD PC sequences that resolve to boot command strings.
needles=(b"boot-recovery",b"boot-fastboot",b"normal",b"recovery",b"fastboot")
refs=[]
for start,end in [(0x48000000,0x48010000),(0x48020000,0x48031000),(0x48021000,0x48023000)]:
 ins=dis(start,end-start)
 for j,x in enumerate(ins):
  m=re.search(r"\[pc,\s*#(0x[0-9a-fA-F]+|\d+)\]",x.op_str)
  if not m: continue
  lit=((x.address+4)&~3)+int(m.group(1),0); w=get(lit,4)
  if len(w)!=4: continue
  val=struct.unpack("<I",w)[0]
  for y in ins[j+1:j+4]:
   if y.mnemonic=="add" and ", pc" in y.op_str:
    target=(val+y.address+4)&0xffffffff; data=get(target,120)
    if any(n in data for n in needles):
     refs.append(f"0x{x.address:08X} LDR literal@0x{lit:08X}=0x{val:08X}; ADD@0x{y.address:08X}; target=0x{target:08X}: {data.split(bytes([0]),1)[0].decode('ascii','replace')}")
    break
save("BOOT_COMMAND_STRING_XREFS.txt",refs)
# Find all direct branch/call sites to reboot helper and known command dispatcher.
targets={0x4800788C:"helper_0788C",0x48026F50:"generic_26F50",0x48026EB4:"generic_26EB4",
0x48021650:"boot_cmd_21650",0x480218A0:"event_218A0",0x4802E7EC:"bootmode_renderer"}
hits={k:[] for k in targets}
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
 rows.append(f"\n{n} 0x{d:08X}: {len(hits[d])}")
 rows.extend(f"  0x{x:08X}" for x in hits[d][:500])
save("BOOT_ACTION_CALLERS.txt",rows)
summary=["Stage 27 read-only boot action and command string analysis.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 27 workflow.
