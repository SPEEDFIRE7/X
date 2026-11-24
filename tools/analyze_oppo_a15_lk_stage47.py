#!/usr/bin/env python3
"""Stage 47: map state-object address into the embedded FDT structure. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage47"); OUT.mkdir(exist_ok=True)
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
sha=hashlib.sha256(raw).hexdigest()
fdt=raw.find(b"\xd0\x0d\xfe\xed")
if fdt<0: raise SystemExit("FDT not found")
h=struct.unpack_from(">10I",raw,fdt); _,total,os_,ostr,_,ver,last,_,ss,sz=h
strings=raw[fdt+ostrings:fdt+ostrings+ss] if False else raw[fdt+ostr:fdt+ostr+sz]
data=raw[fdt+os_:fdt+os_+sz]
target=0x483C89E4-BASE
target_struct=target-(fdt+os_)
pos=0; stack=[]; records=[]; current=None
while pos+4<=len(data):
 start=pos; tok=struct.unpack_from(">I",data,pos)[0]; pos+=4
 if tok==1:
  e=data.find(b"\0",pos)
  if e<0: break
  name=data[pos:e]; pos=(e+4)&~3; stack.append(name)
  records.append((start,pos,b"BEGIN",b"/"+b"/".join(stack),b""))
 elif tok==2:
  path=b"/"+b"/".join(stack)
  records.append((start,pos,b"END_NODE",path,b""))
  if stack: stack.pop()
 elif tok==3:
  if pos+8>len(data): break
  ln,no=struct.unpack_from(">II",data,pos); pos+=8
  valstart=pos; val=data[pos:pos+ln]; pos=(pos+ln+3)&~3
  if no>=len(strings): name=b"<bad-nameoff>"
  else:
   e=strings.find(b"\0",no); name=strings[no:e] if e>=0 else b"<bad-name>"
  path=b"/"+b"/".join(stack)
  records.append((start,pos,b"PROP",path,name+ b"="+val))
 elif tok==4: records.append((start,pos,b"NOP",b"/"+b"/".join(stack),b""))
 elif tok==9:
  records.append((start,pos,b"END",b"/",b"")); break
 else:
  records.append((start,pos,b"UNKNOWN",b"/"+b"/".join(stack),f"0x{tok:X}".encode())); break
lines=[
 f"FDT file offset=0x{fdt:X} VA=0x{BASE+fdt:08X}",
 f"FDT struct file offset=0x{fdt+os_:X} VA=0x{BASE+fdt+os_:08X}",
 f"state candidate VA=0x483C89E4 file offset=0x{target:X}",
 f"state candidate offset within struct=0x{target_struct:X}",
 f"sha256={sha}"
]
for s,e,kind,path,payload in records:
 if abs(s-target_struct)<=0x80 or abs(e-target_struct)<=0x80:
  lines.append(f"struct+0x{s:06X}..0x{e:06X} {kind.decode()} path={path.decode(errors='replace')} payload={payload!r}")
save("STATE_ADDRESS_FDT_CONTEXT.txt",lines)
save("SUMMARY.txt",[
 "Stage 47 mapped 0x483C89E4 into the embedded FDT token stream.",
 f"sha256={sha}",f"FDT_offset=0x{fdt:X}",f"target_struct_offset=0x{target_struct:X}",
 "This determines whether the address is actual FDT property data or a separate state object.",
 "No LK image bytes modified."
])
print("\n".join(lines[:5]))
