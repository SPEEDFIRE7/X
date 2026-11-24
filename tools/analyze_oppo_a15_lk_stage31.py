#!/usr/bin/env python3
"""Stage 31: resolve boot-mode state globals and command dispatch literals. READ ONLY."""
import os,struct,hashlib,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage31"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("boot_check_21548.txt",0x48021548,0x280),("boot_loop_03F50.txt",0x48003F50,0x240),
("boot_state_05378.txt",0x48005378,0xA0),("misc_parser_218A0.txt",0x480218A0,0x90),
("boot_state_tasks_07E30.txt",0x48007E30,0x50),("boot_state_tasks_07F98.txt",0x48007F98,0x60)]
for n,va,sz in regions: save(n,[fmt(i) for i in dis(va,sz)])
refs=[]
for name,va,n in regions:
 ins=dis(va,n)
 for j,x in enumerate(ins):
  m=re.search(r"\[pc,\s*#(0x[0-9a-fA-F]+|\d+)\]",x.op_str)
  if not m: continue
  lit=((x.address+4)&~3)+int(m.group(1),0); w=get(lit,4)
  if len(w)!=4: continue
  val=struct.unpack("<I",w)[0]
  for y in ins[j+1:j+4]:
   if y.mnemonic=="add" and ", pc" in y.op_str:
    target=(val+y.address+4)&0xffffffff
    data=get(target,128)
    z=data.split(b"\0",1)[0]
    if z and all(31<c<127 for c in z): desc=z.decode("ascii","replace")
    else: desc=data[:32].hex(" ")
    refs.append(f"{name}: LDR@0x{x.address:08X} literal@0x{lit:08X}=0x{val:08X}; ADD@0x{y.address:08X}; target=0x{target:08X}: {desc}")
    break
save("BOOT_STATE_LITERALS.txt",refs)
summary=["Stage 31 read-only boot state/global analysis.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 31 workflow.
