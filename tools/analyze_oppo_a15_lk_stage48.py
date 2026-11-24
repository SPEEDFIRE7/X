#!/usr/bin/env python3
"""Stage 48: find code references to boot/reboot action strings. READ ONLY."""
import os,struct,hashlib,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage48"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def get(a,n):
 p=a-BASE
 return raw[p:p+n] if 0<=p and p+n<=len(raw) else b""
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
def word(a):
 b=get(a,4)
 return struct.unpack("<I",b)[0] if len(b)==4 else None
sha=hashlib.sha256(raw).hexdigest()
targets={
 "boot-fastboot":0x4808687C,"boot-recovery":0x480868D8,
 "reboot-bootloader":0x48089880,"reboot-recovery":0x48089894,
 "reboot-fastboot":0x480898A4,"power-off-981":0x4806A981,
 "reboot-device":0x4806AA18,"reboot-board":0x4807A774,
 "power-off-7AE38":0x4807AE38,"power-off-88741":0x48088741,
 "reboot-os-88794":0x48088794
}
hits={k:[] for k in targets}
insns=[]
# Decode likely LK code region only; later data may produce false instruction decodes, filtered by exact targets.
end=min(BASE+0x90000,BASE+len(raw))
for ins in md.disasm(get(BASE+0x200,end-(BASE+0x200)),BASE+0x200):
 insns.append(ins)
# Direct absolute pointer and PC-relative LDR -> ADD PC pairs.
for i,ins in enumerate(insns):
 if ins.mnemonic.startswith("ldr") and "[pc" in ins.op_str.lower():
  m=re.search(r"\[pc,\s*#?(0x[0-9a-f]+|[0-9]+)\]",ins.op_str.lower())
  if not m: continue
  imm=int(m.group(1),0)
  lit=((ins.address+4)&~3)+imm
  val=word(lit)
  reg=ins.op_str.split(",",1)[0].strip()
  for name,t in targets.items():
   if val==t: hits[name].append(f"ABS 0x{ins.address:08X}: {ins.mnemonic} {ins.op_str} literal@0x{lit:08X}=0x{val:08X}")
   # Find matching ADD reg,PC within next 4 decoded instructions.
   for j in range(i+1,min(i+5,len(insns))):
    nxt=insns[j]
    if nxt.mnemonic.startswith("add") and nxt.op_str.lower().startswith(reg.lower()+", pc"):
     resolved=(nxt.address+4)+val
     if resolved==t:
      hits[name].append(f"REL 0x{ins.address:08X} -> 0x{nxt.address:08X}: literal@0x{lit:08X}=0x{val:08X}; resolved=0x{resolved:08X}")
# Also scan all aligned words for exact absolute target pointers.
for name,t in targets.items():
 b=struct.pack("<I",t); p=0
 while True:
  p=raw.find(b,p)
  if p<0: break
  hits[name].append(f"WORD file+0x{p:X} VA=0x{BASE+p:08X} contains pointer 0x{t:08X}")
  p+=1
out=[]
for name,items in hits.items():
 out.append(f"[{name}] target=0x{targets[name]:08X} refs={len(items)}")
 out.extend(items[:60] if items else ["  no static reference found in scanned region"])
save("BOOT_ACTION_STRING_XREFS.txt",out)
save("SUMMARY.txt",[
 "Stage 48 scanned code/data for references to boot/reboot/power-off strings.",
 f"image_size={len(raw)}",f"sha256={sha}",
 "References are candidate xrefs only; call-site semantics require surrounding-function inspection.",
 "No LK image bytes modified."
])
print("\n".join(["Stage 48 complete",f"sha256={sha}",f"instructions={len(insns)}"]))

# Trigger after workflow registration.
