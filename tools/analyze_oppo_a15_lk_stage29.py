#!/usr/bin/env python3
"""Stage 29: resolve boot key configuration property names and menu action strings. READ ONLY."""
import os,struct,hashlib,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage29"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("key_config_loader.txt",0x4800512C,0x180),("key_validator.txt",0x480052EC,0x90),
("unlock_flow.txt",0x4802EB60,0x110),("lock_flow.txt",0x4802EC84,0x110),
("bootmode_renderer.txt",0x4802E7EC,0x90)]
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
    target=(val+y.address+4)&0xffffffff; data=get(target,200)
    z=data.split(b"\0",1)[0]
    if z and all(31<c<127 for c in z):
     refs.append(f"{name}: site=0x{x.address:08X}, target=0x{target:08X}: {z.decode('ascii','replace')}")
    else:
     refs.append(f"{name}: site=0x{x.address:08X}, target=0x{target:08X}, raw={data[:40].hex(' ')}")
    break
save("RESOLVED_PROPERTY_AND_MENU_STRINGS.txt",refs)
summary=["Stage 29 read-only key config property and menu string analysis.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))
