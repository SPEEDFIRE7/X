#!/usr/bin/env python3
"""Stage 41: map boot-state producers and consumers. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage41"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(a,n):
 p=a-BASE
 return raw[p:p+n] if 0<=p and p+n<=len(raw) else b""
def dis(a,n): return list(md.disasm(get(a,n),a))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
sha=hashlib.sha256(raw).hexdigest()
save("IMAGE_ID.txt",[f"size={len(raw)}",f"sha256={sha}","READ ONLY"])
# Producer/helper routines called by the main boot-state loop.
funcs=[
 ("pmic_key_or_event_07D04_07E00.txt",0x48007D04,0x120),
 ("pmic_key_or_event_07D48_07E20.txt",0x48007D48,0x180),
 ("pmic_key_or_event_07E30_07F30.txt",0x48007E30,0x180),
 ("pmic_key_or_event_07F40_08020.txt",0x48007F40,0xE0),
 ("pmic_key_or_event_073C8_07480.txt",0x480073C8,0xC0),
 ("pmic_key_or_event_07DFC_07F10.txt",0x48007DFC,0x160),
 ("boot_state_consumer_1EBC8_1ED20.txt",0x4801EBC8,0x158),
 ("boot_state_consumer_418D8_419C0.txt",0x480418D8,0xE8),
 ("parent_state_dispatch_0319A_03590.txt",0x4800319A,0x3F6),
]
for name,a,n in funcs: save(name,[fmt(i) for i in dis(a,n)])
# All aligned pointer occurrences of the confirmed state object and its table.
refs=[]
for p in range(0,len(raw)-3,4):
 v=struct.unpack_from("<I",raw,p)[0]
 if v in (0x483C89E4,0x483C5760,0x483C531C):
  refs.append(f"file+0x{p:08X} VA=0x{BASE+p:08X} word=0x{v:08X}")
save("CONFIRMED_STATE_POINTER_REFS.txt",refs)
# Dump state block bytes and first word separately; classify strings and following fields.
b=get(0x483C89E4,0x180)
save("STATE_OBJECT_HEX.txt",[f"0x{0x483C89E4+i:08X}: "+b[i:i+16].hex(" ") for i in range(0,len(b),16)])
# Collect all exact string hits for likely event/boot state messages.
terms=[b"power key",b"key %d",b"reboot",b"power off",b"recovery",b"fastboot",
       b"normal boot",b"factory",b"download",b"boot mode",b"charging"]
hits=[]
low=raw.lower()
for t in terms:
 p=0
 while True:
  p=low.find(t,p)
  if p<0: break
  sample=raw[p:p+120].split(b"\0",1)[0]
  hits.append(f"VA=0x{BASE+p:08X} {sample!r}")
  p+=1
save("STATE_EVENT_STRINGS.txt",sorted(set(hits)))
save("SUMMARY.txt",[
 "Stage 41 mapped main-loop state producer helpers and parent consumers.",
 f"image_size={len(raw)}",f"sha256={sha}",
 "State object candidate is the shared pointer at 0x483C89E4 via table 0x483C5760.",
 "Numeric state values are not assigned reboot meanings unless producer and consumer paths establish them.",
 "No LK image bytes modified."
])
print("\n".join(["Stage 41 complete",f"sha256={sha}",f"state_pointer_refs={len(refs)}"]))

# Trigger after workflow registration.
