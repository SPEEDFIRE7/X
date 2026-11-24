#!/usr/bin/env python3
"""Stage 46: enumerate key-related nodes/properties in embedded FDT. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage46"); OUT.mkdir(exist_ok=True)
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
sha=hashlib.sha256(raw).hexdigest()
p=raw.find(b"\xd0\x0d\xfe\xed")
if p<0: raise SystemExit("No FDT magic")
h=struct.unpack_from(">10I",raw,p); _,total,os_,ostr,_,ver,last,_,ss,sz=h
strings=raw[p+ostr:p+ostr+sz]; data=raw[p+os_:p+os_+sz]
pos=0; stack=[]; out=[]; matches=[]; allnodes=[]
while pos+4<=len(data):
 t=struct.unpack_from(">I",data,pos)[0]; pos+=4
 if t==1:
  e=data.find(b"\0",pos)
  if e<0: break
  name=data[pos:e]; pos=(e+4)&~3; stack.append(name)
  path=b"/"+b"/".join(x for x in stack if x)
  allnodes.append(path.decode(errors="replace"))
 elif t==2:
  if stack: stack.pop()
 elif t==3:
  if pos+8>len(data): break
  ln,no=struct.unpack_from(">II",data,pos); pos+=8; val=data[pos:pos+ln]; pos=(pos+ln+3)&~3
  if no>=len(strings): continue
  e=strings.find(b"\0",no)
  if e<0: continue
  name=strings[no:e]; path=b"/"+b"/".join(x for x in stack if x)
  if any(x in (path+name+val).lower() for x in [b"key",b"volume",b"power",b"reset",b"kp@"]):
   if len(val)==4: v=f"u32={struct.unpack('>I',val)[0]} raw={val.hex()}"
   else: v=f"len={ln} raw={val.hex()} ascii={val!r}"
   matches.append(f"path={path.decode(errors='replace')} prop={name.decode(errors='replace')} {v}")
 elif t==4: continue
 elif t==9: break
 else: matches.append(f"unknown token 0x{t:X} at 0x{pos-4:X}"); break
save("FDT_KEY_RELATED_NODES.txt",[n for n in allnodes if any(x in n.lower() for x in ["key","volume","power","reset","kp"])])
save("FDT_KEY_RELATED_PROPERTIES.txt",matches)
save("SUMMARY.txt",[
 f"FDT file_offset=0x{p:X} VA=0x{BASE+p:08X}",f"totalsize=0x{total:X}",f"version={ver} last_comp={last}",
 f"sha256={sha}",f"nodes={len(allnodes)} key_related_props={len(matches)}",
 "No LK image bytes modified."
])
print("\n".join([f"FDT offset=0x{p:X}",f"nodes={len(allnodes)}",f"key_related_props={len(matches)}",f"sha256={sha}"]))

# Trigger after workflow registration.
