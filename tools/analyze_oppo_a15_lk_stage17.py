#!/usr/bin/env python3
"""Stage 17: resolve menu text offsets and relative function tables. READ ONLY."""
import os,struct,hashlib,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage17"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
funcs={0x4802EB60:"menu_A",0x4802EC84:"menu_B",0x4802E7EC:"renderer",0x4802E920:"setup_A",0x4802E9B4:"setup_B",0x48003F50:"boot_loop"}
regions=[(0x4802EB60,0x110,"menu_A"),(0x4802EC84,0x110,"menu_B"),(0x4802E7EC,0x100,"renderer"),(0x4802E920,0x90,"setup_A"),(0x4802E9B4,0x90,"setup_B")]
# Resolve each LDR literal followed shortly by ADD of same register, PC.
refs=[]; candidates=[]
for start,n,name in regions:
 ins=dis(start,n)
 for ix,x in enumerate(ins):
  m=re.search(r"\[pc,\s*#(0x[0-9a-fA-F]+|\d+)\]",x.op_str)
  if not m: continue
  reg=x.op_str.split(",")[0].strip()
  lit=((x.address+4)&~3)+int(m.group(1),0); w=get(lit,4)
  if len(w)!=4: continue
  val=struct.unpack("<I",w)[0]
  for y in ins[ix+1:ix+4]:
   if y.mnemonic=="add" and y.op_str.replace(" ","").startswith(reg+",pc"):
    target=(val+y.address+4)&0xffffffff
    data=get(target,128)
    printable=[]
    for mm in re.finditer(rb"[\x20-\x7e]{4,}\x00",data):
     printable.append(mm.group(0)[:-1].decode("ascii","replace"))
    refs.append(f"{name}: LDR@0x{x.address:08X} literal@0x{lit:08X}=0x{val:08X}; ADD@0x{y.address:08X}; target=0x{target:08X}; bytes={data[:24].hex(' ')}; strings={printable}")
    candidates.append(target)
    break
save("PIC_STRING_AND_DATA_TARGETS.txt",refs)
# Search every byte alignment for absolute pointers, offsets, and signed PC-relative offsets.
needles={}
for va,name in funcs.items():
 off=va-BASE
 for v,kind in ((va|1,"absolute_thumb"),(va,"absolute_even"),(off|1,"image_offset_thumb"),(off,"image_offset_even"),(off-0x200,"payload_offset")):
  needles.setdefault(v,[]).append(f"{name}:{kind}")
hits=[]
for p in range(0,len(raw)-3):
 v=struct.unpack_from("<I",raw,p)[0]
 if v in needles:
  hits.append(f"file+0x{p:08X} VA=0x{BASE+p:08X} value=0x{v:08X} -> {','.join(needles[v])}")
 # PC-relative signed delta stored as 32-bit value from this slot.
 for va,name in funcs.items():
  if ((BASE+p+v)&0xffffffff)==va or ((BASE+p+v)|1)&0xffffffff==(va|1):
   hits.append(f"file+0x{p:08X} VA=0x{BASE+p:08X} rel32=0x{v:08X} -> {name} 0x{va:08X}")
save("FUNCTION_TABLE_RELATIVE_REFS.txt",hits or ["No direct absolute/offset/rel32 references found."])
summary=["Stage 17 read-only relative reference and menu text scan.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 17 workflow.
