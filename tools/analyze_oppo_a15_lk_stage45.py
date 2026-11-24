#!/usr/bin/env python3
"""Stage 45: locate and parse embedded FDT blobs for keypad key values. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage45"); OUT.mkdir(exist_ok=True)
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
sha=hashlib.sha256(raw).hexdigest()
save("IMAGE_ID.txt",[f"size={len(raw)}",f"sha256={sha}","READ ONLY"])
MAG=b"\xd0\x0d\xfe\xed"
candidates=[]; p=0
while True:
 p=raw.find(MAG,p)
 if p<0: break
 if p+40<=len(raw):
  h=struct.unpack_from(">10I",raw,p)
  magic,total,off_struct,off_strings,off_rsv,ver,last,boot,size_strings,size_struct=h
  if 40<=total<=len(raw)-p and off_struct<total and off_strings<total and size_struct<=total-off_struct and size_strings<=total-off_strings:
   candidates.append((p,h))
 p+=1
summary=[f"FDT candidates={len(candidates)}"]
keyprops={b"mediatek,kpd-sw-pwrkey",b"mediatek,kpd-hw-pwrkey",b"mediatek,kpd-sw-rstkey",
 b"mediatek,kpd-hw-rstkey",b"mediatek,kpd-use-extend-type",b"mediatek,kpd-hw-recovery-key",
 b"mediatek,kpd-hw-factory-key",b"mediatek,kpd-hw-map-num"}
for idx,(base,h) in enumerate(candidates):
 magic,total,off_struct,off_strings,off_rsv,ver,last,boot,size_strings,size_struct=h
 sbase=base+off_strings; strings=raw[sbase:sbase+size_strings]
 structdata=raw[base+off_struct:base+off_struct+size_struct]
 out=[f"FDT#{idx} file_offset=0x{base:X} VA=0x{BASE+base:08X}",f"totalsize=0x{total:X}",f"off_struct=0x{off_struct:X}",f"off_strings=0x{off_strings:X}",f"version={ver} last_comp={last}",f"size_struct=0x{size_struct:X} size_strings=0x{size_strings:X}"]
 pos=0; stack=[]; current_props=[]; found=False
 while pos+4<=len(structdata):
  tok=struct.unpack_from(">I",structdata,pos)[0]; pos+=4
  if tok==1:
   end=structdata.find(b"\0",pos)
   if end<0: break
   name=structdata[pos:end]; pos=(end+4)&~3
   stack.append(name)
  elif tok==2:
   if stack: stack.pop()
  elif tok==3:
   if pos+8>len(structdata): break
   length,nameoff=struct.unpack_from(">II",structdata,pos); pos+=8
   val=structdata[pos:pos+length]; pos=(pos+length+3)&~3
   if nameoff>=len(strings): continue
   ne=strings.find(b"\0",nameoff)
   if ne<0: continue
   name=strings[nameoff:ne]
   path=b"/"+b"/".join(x for x in stack if x)
   if b"kp@10010000" in path or name in keyprops:
    if name in keyprops or b"kp@10010000" in path:
     found=True
     if len(val)==4: v=f"u32_be={struct.unpack('>I',val)[0]} u32_le={struct.unpack('<I',val)[0]}"
     elif len(val)==0: v="boolean_property"
     else: v=f"bytes={val.hex()} ascii={val!r}"
     out.append(f"path={path.decode(errors='replace')} property={name.decode(errors='replace')} len={length} {v}")
  elif tok==4: continue
  elif tok==9: break
  else:
   out.append(f"UNKNOWN_TOKEN=0x{tok:X} at struct+0x{pos-4:X}"); break
 if not found: out.append("No keypad node/key properties parsed in this FDT.")
 save(f"FDT_{idx}_KEYPAD_PROPERTIES.txt",out)
 summary.append(f"FDT#{idx} offset=0x{base:X} size=0x{total:X} keypad_data={found}")
# Raw nearby context for the known path string location.
for s in [b"/kp@10010000",b"mediatek,kpd-hw-pwrkey",b"mediatek,kpd-hw-recovery-key"]:
 p=0
 while True:
  p=raw.find(s,p)
  if p<0: break
  summary.append(f"string {s.decode()} at file+0x{p:X} VA=0x{BASE+p:08X}")
  p+=1
save("SUMMARY.txt",summary+["No image bytes modified."])
print("\n".join(summary))

# Trigger after workflow registration.
