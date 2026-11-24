#!/usr/bin/env python3
"""Fast Stage 4 targeted xref scan. Read-only; exact address reconstruction."""
import os,struct,hashlib,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0); PREFIX=int(os.getenv("PAYLOAD_OFFSET","0x200"),0)
OUT=Path("menu-xref-stage4"); OUT.mkdir(exist_ok=True)
raw=IMAGE.read_bytes(); data=raw[PREFIX:]; END=BASE+len(data)
terms=[b"Select Boot Mode:",b"VOLUME_UP to select",b"Recovery    Mode",b"Fastboot    Mode",b"Normal      Boot",b"Unlock bootloader?",b"lock bootloader?",b"Volume UP/Down buttons",b"Yes (Volume Down):Unlock",b"No (Volume UP):Do not unlock bootloader.",b"Yes (Volume Down):Lock bootloader.",b"No (Volume UP):Do not lock bootloader.",b"download",b"recovery",b"/recovery",b"boot-fastboot",b"boot-recovery",b"reboot-bootloader",b"reboot-recovery",b"reboot-fastboot",b"singlebootloader",b"Set_RTC_Fastboot_Mode",b"mt_power_off new",b"mediatek,kpd-hw-recovery-key",b"kpd_use_extend_type",b"MT65XX_RECOVERY_KEY",b"power key is pressed",b"mtk detect key function pmic_detect_homekey pressed"]
strings={}
for t in terms:
 p=0
 while True:
  p=data.find(t,p)
  if p<0: break
  strings[BASE+p]=t.decode("ascii","replace"); p+=1
targets=set(strings)
def u32(va):
 o=va-BASE
 return struct.unpack_from("<I",data,o)[0] if 0<=o<=len(data)-4 else None
ptr=[]
for o in range(0,len(data)-3,4):
 v=struct.unpack_from("<I",data,o)[0]
 if v in targets: ptr.append((BASE+o,v))
# Fast decoder output: address,size,mnemonic,operand string
tm=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
am=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
thumb={a-BASE:(a,s,m.lower(),op) for a,s,m,op in tm.disasm_lite(data,BASE)}
arm={a-BASE:(a,s,m.lower(),op) for a,s,m,op in am.disasm_lite(data,BASE)}
regpat=r"(?:r(?:1[0-2]|[0-9])|ip|fp|sl|sb|lr|sp|pc)"
ldrpat=re.compile(r"^\s*("+regpat+r")\s*,\s*\[pc\s*,\s*#?(-?0x[0-9a-f]+|-?[0-9]+)\s*\]",re.I)
addpat=re.compile(r"^\s*("+regpat+r")\s*,\s*pc\s*$",re.I)
hits=[]
for off,(addr,size,m,op) in thumb.items():
 if m=="adr":
  # Capstone normally resolves ADR to an absolute immediate.
  z=re.search(r",\s*#?(0x[0-9a-f]+)",op,re.I)
  if z and int(z.group(1),16) in targets: hits.append(("THUMB",addr,int(z.group(1),16),"ADR",op))
 z=ldrpat.match(op) if m.startswith("ldr") else None
 if z:
  reg=z.group(1).lower(); disp=int(z.group(2),0); slot=(((addr+4)&~3)+disp)&0xffffffff; lit=u32(slot)
  if lit is not None:
   for d in (2,4,6,8,10,12):
    nxt=thumb.get(off+d)
    if not nxt: continue
    na,ns,nm,no=nxt; a=addpat.match(no) if nm.startswith("add") else None
    if a and a.group(1).lower()==reg:
     final=((((na+4)&~3)+lit)&0xffffffff)
     if final in targets: hits.append(("THUMB",addr,final,f"LDR+ADD_PC(+{d})",f"{op}; {nm} {no}; literal=0x{lit:08X} slot=0x{slot:08X}"))
# ARM analogue, limited to actual decoded instruction stream.
for off,(addr,size,m,op) in arm.items():
 z=ldrpat.match(op) if m.startswith("ldr") else None
 if z:
  reg=z.group(1).lower(); disp=int(z.group(2),0); slot=(addr+8+disp)&0xffffffff; lit=u32(slot)
  if lit is not None:
   for d in (4,8,12,16):
    nxt=arm.get(off+d)
    if not nxt: continue
    na,ns,nm,no=nxt
    # ARM ADD syntax: rd, rn, rm. Match rd=loaded reg and rm=pc.
    parts=[p.strip().lower() for p in no.split(",")]
    if nm.startswith("add") and len(parts)>=3 and parts[0]==reg and parts[-1]=="pc":
     final=(na+8+lit)&0xffffffff
     if final in targets: hits.append(("ARM",addr,final,f"LDR+ADD_PC(+{d})",f"{op}; {nm} {no}; literal=0x{lit:08X}"))
def wr(n,ls): (OUT/n).write_text("\n".join(ls)+("\n" if ls else ""))
uniq=sorted(set(hits))
wr("string_addresses.txt",[f"0x{a:08X} {s}" for a,s in sorted(strings.items())])
wr("exact_code_xrefs.txt",[f"{md} site=0x{site:08X} -> 0x{t:08X} [{strings[t]}] via={kind}: {ctx}" for md,site,t,kind,ctx in uniq])
wr("absolute_pointer_hits.txt",[f"slot=0x{s:08X} file_off=0x{PREFIX+s-BASE:X} -> 0x{t:08X} [{strings[t]}]" for s,t in ptr])
ctx=[]
for md,site,t,kind,detail in uniq:
 ctx.append(f"--- {md} 0x{site:08X} -> 0x{t:08X} {strings[t]} {kind}: {detail}")
 tab=thumb if md=="THUMB" else arm; step=2 if md=="THUMB" else 4
 for q in range(site-12,site+20,step):
  v=tab.get(q-BASE)
  if v: ctx.append(f"  0x{v[0]:08X}: {v[2]:8} {v[3]}")
wr("xref_context.txt",ctx)
summary=["Oppo A15 LK stage-4 fast targeted xref scan (READ ONLY)",f"image={IMAGE}",f"sha256={hashlib.sha256(raw).hexdigest()}",f"size={len(raw)} payload_offset=0x{PREFIX:X} load_base=0x{BASE:08X}",f"target_string_occurrences={len(strings)}",f"code_scan_end=0x{BASE+scan_end:08X}",f"thumb_candidate_decodes={len(thumb)}",f"arm_candidate_decodes={len(arm)}",f"exact_code_xrefs={len(uniq)}",f"absolute_pointer_hits={len(ptr)}","Methods: exact ADR, PC-relative literal LDR followed by ADD PC, absolute aligned pointer values.","Linear decoding may interpret some data as instructions; exact target match and surrounding context are required for validation.","No image bytes are modified."]
(OUT/"SUMMARY.txt").write_text("\n".join(summary)+"\n"); print("\n".join(summary))

# Trigger optimized stage 4 scan.

# Re-run Stage 4 after operand parser fix.

# Trigger code-region candidate scan.
