#!/usr/bin/env python3
"""Oppo A15 LK Stage 5: resynchronizing whole-image ARM/Thumb scan.
Read-only candidate analysis; reconstructs PIC LDR-literal + ADD-PC references.
"""
import os,struct,hashlib,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0); PREFIX=int(os.getenv("PAYLOAD_OFFSET","0x200"),0)
OUT=Path("menu-xref-stage5"); OUT.mkdir(exist_ok=True)
raw=IMAGE.read_bytes(); data=raw[PREFIX:]; N=len(data)
terms=[b"Select Boot Mode:",b"VOLUME_UP to select",b"Recovery    Mode",b"Fastboot    Mode",b"Normal      Boot",b"Unlock bootloader?",b"lock bootloader?",b"Volume UP/Down buttons",b"Yes (Volume Down):Unlock",b"No (Volume UP):Do not unlock bootloader.",b"Yes (Volume Down):Lock bootloader.",b"No (Volume UP):Do not lock bootloader.",b"download",b"recovery",b"/recovery",b"boot-fastboot",b"boot-recovery",b"reboot-bootloader",b"reboot-recovery",b"reboot-fastboot",b"singlebootloader",b"Set_RTC_Fastboot_Mode",b"mt_power_off new",b"mediatek,kpd-hw-recovery-key",b"kpd_use_extend_type",b"MT65XX_RECOVERY_KEY",b"power key is pressed",b"mtk detect key function pmic_detect_homekey pressed"]
strings={}
for t in terms:
 p=0
 while True:
  p=data.find(t,p)
  if p<0: break
  strings[BASE+p]=t.decode("ascii","replace"); p+=1
targets=set(strings)
ptr={}
for off in range(0,N-3,4):
 v=struct.unpack_from("<I",data,off)[0]
 if v in targets: ptr[BASE+off]=v
def word(va):
 o=va-BASE
 return struct.unpack_from("<I",data,o)[0] if 0<=o<=N-4 else None
def ascii_at(va):
 o=va-BASE
 if not 0<=o<N: return ""
 b=data[o:o+80].split(b"\0",1)[0]
 return "".join(chr(x) if 32<=x<127 else "." for x in b[:72])
tm=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); tm.detail=True
am=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); am.detail=True
# Collect decoded instruction starts by resynchronizing after invalid bytes.
def sweep(md,step):
 out={}; off=0
 while off+2<=N:
  it=md.disasm(data[off:min(N,off+4)],BASE+off,count=1)
  ins=next(it,None)
  if ins is None:
   off+=step; continue
  out[off]=ins
  off+=ins.size
 return out
thumb=sweep(tm,2); arm=sweep(am,4)
hits=[]; literal_refs=[]; examined=0
# Direct address and PIC pattern matching with exact computed VA.
for mode,insmap in (("THUMB",thumb),("ARM",arm)):
 for off,ins in insmap.items():
  examined+=1; m=ins.mnemonic.lower(); ops=ins.operands; addr=BASE+off
  # ADR exact absolute target
  if m=="adr" and len(ops)>=2 and getattr(ops[1],"type",0)==2:
   val=ops[1].imm & 0xffffffff
   if val in targets: hits.append((mode,addr,val,"ADR",ins.op_str))
  # LDR literal -> offset/pointer, then ADD same register, PC.
  if not (m.startswith("ldr") and len(ops)>=2 and getattr(ops[1],"type",0)==3 and ins.reg_name(ops[1].mem.base)=="pc"):
   continue
  reg=ins.reg_name(ops[0].reg)
  pcbase=((addr+4)&~3) if mode=="THUMB" else addr+8
  slot=(pcbase+ops[1].mem.disp)&0xffffffff; lit=word(slot)
  if lit is None: continue
  literal_refs.append((mode,addr,slot,lit,reg,ins.op_str))
  # LDR may directly load pointer-table slot's string pointer.
  if lit in targets: hits.append((mode,addr,lit,"LDR_LITERAL_VALUE",ins.op_str))
  if lit in ptr:
   hits.append((mode,addr,ptr[lit],"LDR_TO_POINTER_SLOT",f"{ins.op_str}; literal=0x{lit:08X}"))
  # inspect following instructions in same mode for register + PC additions.
  for delta in (2,4,6,8,10,12,14,16,20,24):
   nxt=insmap.get(off+delta)
   if not nxt: continue
   nm=nxt.mnemonic.lower(); no=nxt.operands; target=None
   if mode=="THUMB" and nm.startswith("add") and len(no)>=2 and nxt.reg_name(no[0].reg)==reg and nxt.reg_name(no[1].reg)=="pc":
    # Thumb ADD Rd, PC uses architectural PC = Align(insn_addr+4,4)
    target=((((BASE+off+delta)+4)&~3)+lit)&0xffffffff
   elif mode=="ARM" and nm.startswith("add") and len(no)>=3 and nxt.reg_name(no[0].reg)==reg and nxt.reg_name(no[2].reg)=="pc":
    target=(BASE+off+delta+8+lit)&0xffffffff
   if target is not None:
    if target in targets: hits.append((mode,addr,target,f"LDR_ADD_PC_+{delta}",f"{ins.op_str}; {nxt.mnemonic} {nxt.op_str}; literal=0x{lit:08X}; slot=0x{slot:08X}"))
    elif target in ptr: hits.append((mode,addr,ptr[target],f"LDR_ADD_PC_TO_POINTER_+{delta}",f"computed_slot=0x{target:08X}; {ins.op_str}; {nxt.mnemonic} {nxt.op_str}; literal=0x{lit:08X}"))
# output
def wr(name,lines): (OUT/name).write_text("\n".join(lines)+("\n" if lines else ""))
uniq=sorted(set(hits))
wr("SUMMARY.txt",["Oppo A15 LK stage-5 resynchronizing whole-image scan (READ ONLY)",f"image={IMAGE}",f"sha256={hashlib.sha256(raw).hexdigest()}",f"size={len(raw)} payload_offset=0x{PREFIX:X} load_base=0x{BASE:08X}",f"target_strings={len(strings)}",f"thumb_decoded={len(thumb)}",f"arm_decoded={len(arm)}",f"decoded_candidates_total={examined}",f"literal_loads_examined={len(literal_refs)}",f"exact_reconstructed_xrefs={len(uniq)}",f"absolute_pointer_slots={len(ptr)}","Sweep resynchronizes after invalid bytes; linear decoding can still interpret data as instructions.","All reported xrefs require context validation. No image bytes modified."])
wr("string_addresses.txt",[f"0x{a:08X} {s}" for a,s in sorted(strings.items())])
wr("pointer_slots.txt",[f"slot=0x{slot:08X} -> 0x{target:08X} [{strings[target]}]" for slot,target in sorted(ptr.items())])
wr("literal_loads.txt",[f"{mode} site=0x{site:08X} slot=0x{slot:08X} value=0x{val:08X} reg={reg} {op}" for mode,site,slot,val,reg,op in literal_refs])
wr("xref_candidates.txt",[f"{mode} site=0x{site:08X} -> 0x{target:08X} [{strings[target]}] via={kind}: {ctx}" for mode,site,target,kind,ctx in uniq])
ctx=[]
for mode,site,target,kind,detail in uniq:
 ctx.append(f"--- {mode} site=0x{site:08X} -> 0x{target:08X} [{strings[target]}] {kind}: {detail}")
 insmap=thumb if mode=="THUMB" else arm; step=2 if mode=="THUMB" else 4
 for q in range(site-16,site+28,step):
  ii=insmap.get(q-BASE)
  if ii: ctx.append(f"  0x{ii.address:08X}: {ii.mnemonic:8} {ii.op_str}")
 ctx.append(f"  TARGET_BYTES: {ascii_at(target)}")
wr("xref_context.txt",ctx)
print((OUT/"SUMMARY.txt").read_text())
