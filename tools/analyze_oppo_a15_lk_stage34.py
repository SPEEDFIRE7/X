#!/usr/bin/env python3
"""Stage 34: dump LK boot-state global pointer table and resolve code literal offsets. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage34"); OUT.mkdir(exist_ok=True)
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
tables=[("global_table_483C531C.txt",0x483C531C,0x600),("global_table_483C5760.txt",0x483C5760,0x180),
("global_table_483C419C.txt",0x483C419C,0x180),("global_table_483C5xxx.txt",0x483C5000,0x600)]
for name,start,size in tables:
 b=get(start,size); rows=[f"{name} base=0x{start:08X} size=0x{size:X}"]
 for off in range(0,len(b)-3,4):
  v=struct.unpack_from("<I",b,off)[0]
  if v and (v>=BASE or v<0x10000000):
   rows.append(f"+0x{off:03X} VA 0x{start+off:08X}: 0x{v:08X}"+(f" -> image+0x{v-BASE:X}" if BASE<=v<BASE+len(raw) else ""))
 save(name,rows)
# Extract PC-relative literal words in the boot loop and boot state parser.
lit=[]
for start,end in [(0x48003F50,0x48004188),(0x48021548,0x480217A8)]:
 # manually decode only 16-bit/32-bit LDR literal forms using raw halfwords
 for p in range(start-BASE,end-BASE-3,2):
  h=struct.unpack_from("<H",raw,p)[0]
  # 16-bit LDR literal: 01001 Rt imm8
  if (h&0xF800)==0x4800:
   imm=(h&0xff)*4; va=BASE+p; lva=((va+4)&~3)+imm
   w=get(lva,4)
   if len(w)==4:
    v=struct.unpack("<I",w)[0]; lit.append(f"0x{va:08X}: LDR literal@0x{lva:08X}=0x{v:08X}")
save("BOOT_CODE_LITERAL_WORDS.txt",lit)
summary=["Stage 34 read-only boot global table dump.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))

# Trigger Stage 34 workflow.
