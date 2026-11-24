#!/usr/bin/env python3
"""Stage 33: inspect boot result state dispatch and final reboot/boot branches. READ ONLY."""
import os,struct,hashlib,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage33"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("parent_dispatch_032FA.txt",0x480032FA,0x3A0),("parent_dispatch_03560.txt",0x48003560,0x180),
("parent_dispatch_03320.txt",0x48003320,0x220),("function_1EBC8.txt",0x4801EBC8,0x100),
("function_418D8.txt",0x480418D8,0x100),("function_36720.txt",0x48036720,0x100),
("function_1B614.txt",0x4801B614,0x100),("function_1B040.txt",0x4801B040,0x100),
("function_1E9F8.txt",0x4801E9F8,0x100)]
for n,va,sz in regions: save(n,[fmt(i) for i in dis(va,sz)])
targets={va:n for n,va,sz in regions}; hits={v:[] for v in targets}
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
 rows.append(f"\n{n} 0x{d:08X}: {len(hits[d])} callers")
 rows.extend(f"  0x{x:08X}" for x in hits[d][:400])
save("RESULT_HANDLER_CALLERS.txt",rows)
# Strings from the parent state dispatch and likely handlers.
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
    target=(val+y.address+4)&0xffffffff; data=get(target,120); z=data.split(b"\0",1)[0]
    if z and all(31<c<127 for c in z):
     refs.append(f"{name}: 0x{x.address:08X} -> 0x{target:08X}: {z.decode('ascii','replace')}")
    break
save("RESULT_HANDLER_STRINGS.txt",refs)
summary=["Stage 33 read-only final boot result dispatcher analysis.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 33 workflow.
