#!/usr/bin/env python3
"""Stage 4: whole-image targeted ARM/Thumb xref scan for Oppo A15 LK.
Read-only. Exact target-address matching; no binary patching.
"""
import os, struct, hashlib
from pathlib import Path
from collections import defaultdict
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img"))
BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
PREFIX=int(os.getenv("PAYLOAD_OFFSET","0x200"),0)
OUT=Path("menu-xref-stage4"); OUT.mkdir(exist_ok=True)
raw=IMAGE.read_bytes(); data=raw[PREFIX:]; END=BASE+len(data)
terms=[
 b"Select Boot Mode:",b"VOLUME_UP to select",b"Recovery    Mode",b"Fastboot    Mode",b"Normal      Boot",
 b"Unlock bootloader?",b"lock bootloader?",b"Volume UP/Down buttons",
 b"Yes (Volume Down):Unlock",b"No (Volume UP):Do not unlock bootloader.",
 b"Yes (Volume Down):Lock bootloader.",b"No (Volume UP):Do not lock bootloader.",
 b"download",b"recovery",b"/recovery",b"boot-fastboot",b"boot-recovery",
 b"reboot-bootloader",b"reboot-recovery",b"reboot-fastboot",b"singlebootloader",
 b"Set_RTC_Fastboot_Mode",b"mt_power_off new",
 b"mediatek,kpd-hw-recovery-key",b"kpd_use_extend_type",b"MT65XX_RECOVERY_KEY",
 b"power key is pressed",b"mtk detect key function pmic_detect_homekey pressed"
]
strings={}
for t in terms:
 start=0
 while True:
  off=data.find(t,start)
  if off<0: break
  strings[BASE+off]=t.decode("ascii","replace")
  start=off+1
targets=set(strings)
def read32(va):
 off=va-BASE
 return struct.unpack_from("<I",data,off)[0] if 0<=off<=len(data)-4 else None
def insn_at(off,mode):
 cm=(CS_MODE_THUMB if mode=="thumb" else CS_MODE_ARM)|CS_MODE_LITTLE_ENDIAN
 md=Cs(CS_ARCH_ARM,cm); md.detail=True
 return next(md.disasm(data[off:off+4],BASE+off,count=1),None)
hits=[]; pointer_hits=[]; decoded=0
# Exact absolute pointers in aligned data words.
for off in range(0,len(data)-3,4):
 v=struct.unpack_from("<I",data,off)[0]
 if v in targets: pointer_hits.append((BASE+off,v))
# Scan halfword-aligned Thumb candidates. Only report exact reconstructed target.
thumb_ins={}
for off in range(0,len(data)-3,2):
 ins=insn_at(off,"thumb")
 if ins: thumb_ins[off]=ins; decoded+=1
for off,ins in thumb_ins.items():
 m=ins.mnemonic.lower(); ops=ins.operands; addr=BASE+off
 if m=="adr" and len(ops)>1 and ops[1].type==ARM_OP_IMM and (ops[1].imm&0xffffffff) in targets:
  v=ops[1].imm&0xffffffff; hits.append(("THUMB",addr,v,"ADR",ins.mnemonic+" "+ins.op_str))
 # Literal LDR followed by ADD same register, PC.
 if m.startswith("ldr") and len(ops)>1 and ops[0].type==ARM_OP_REG and ops[1].type==ARM_OP_MEM and ops[1].mem.base==ARM_REG_PC:
  pcbase=((addr+4)&~3); slot=(pcbase+ops[1].mem.disp)&0xffffffff; lit=read32(slot)
  if lit is None: continue
  reg=ops[0].reg
  for delta in (2,4,6,8,10,12):
   nxt=thumb_ins.get(off+delta)
   if not nxt: continue
   no=nxt.operands
   if nxt.mnemonic.lower().startswith("add") and len(no)>=2 and no[0].type==ARM_OP_REG and no[1].type==ARM_OP_REG and no[0].reg==reg and no[1].reg==ARM_REG_PC:
    addpc=((BASE+off+delta+4)&~3)
    target=(addpc+lit)&0xffffffff
    if target in targets:
     hits.append(("THUMB",addr,target,f"LDR+ADD_PC(+{delta})",f"{ins.mnemonic} {ins.op_str}; {nxt.mnemonic} {nxt.op_str}; literal=0x{lit:08X} slot=0x{slot:08X}"))
 # MOVW/MOVT pair in nearby straight-line bytes (same register, <= 16 bytes)
 if m=="movw" and len(ops)>1 and ops[0].type==ARM_OP_REG and ops[1].type==ARM_OP_IMM:
  reg=ops[0].reg; low=ops[1].imm&0xffff
  for delta in (4,6,8,10,12,14,16):
   nxt=thumb_ins.get(off+delta)
   if nxt and nxt.mnemonic.lower()=="movt" and len(nxt.operands)>1 and nxt.operands[0].type==ARM_OP_REG and nxt.operands[0].reg==reg and nxt.operands[1].type==ARM_OP_IMM:
    target=((nxt.operands[1].imm&0xffff)<<16)|low
    if target in targets: hits.append(("THUMB",addr,target,"MOVW+MOVT",f"{ins.op_str}; {nxt.op_str}"))
# ARM 4-byte aligned scan
for off in range(0,len(data)-3,4):
 ins=insn_at(off,"arm")
 if not ins: continue
 addr=BASE+off; m=ins.mnemonic.lower(); ops=ins.operands
 if m=="adr" and len(ops)>1 and ops[1].type==ARM_OP_IMM and (ops[1].imm&0xffffffff) in targets:
  v=ops[1].imm&0xffffffff; hits.append(("ARM",addr,v,"ADR",ins.mnemonic+" "+ins.op_str))
 if m.startswith("ldr") and len(ops)>1 and ops[0].type==ARM_OP_REG and ops[1].type==ARM_OP_MEM and ops[1].mem.base==ARM_REG_PC:
  slot=(addr+8+ops[1].mem.disp)&0xffffffff; lit=read32(slot)
  if lit is not None:
   for delta in (4,8,12,16):
    nxt=insn_at(off+delta,"arm")
    if nxt and nxt.mnemonic.lower().startswith("add") and len(nxt.operands)>=3 and nxt.operands[0].type==ARM_OP_REG and nxt.operands[1].type==ARM_OP_REG and nxt.operands[0].reg==ops[0].reg and nxt.operands[2].type==ARM_OP_REG and nxt.operands[2].reg==ARM_REG_PC:
     target=((BASE+off+delta+8)+lit)&0xffffffff
     if target in targets: hits.append(("ARM",addr,target,f"LDR+ADD_PC(+{delta})",f"{ins.mnemonic} {ins.op_str}; {nxt.mnemonic} {nxt.op_str}; literal=0x{lit:08X}"))
def out(name,lines): (OUT/name).write_text("\n".join(lines)+("\n" if lines else ""))
out("string_addresses.txt",[f"0x{a:08X} {s}" for a,s in sorted(strings.items())])
out("exact_code_xrefs.txt",[f"{mode} site=0x{site:08X} -> 0x{target:08X} [{strings[target]}] via={kind}: {ctx}" for mode,site,target,kind,ctx in sorted(set(hits))])
out("absolute_pointer_hits.txt",[f"slot=0x{slot:08X} file_off=0x{PREFIX+slot-BASE:X} -> 0x{target:08X} [{strings[target]}]" for slot,target in pointer_hits])
# Targeted context snippets around each exact hit, preserving instruction addresses.
ctx=[]
for mode,site,target,kind,detail in sorted(set(hits)):
 ctx.append(f"--- {mode} hit 0x{site:08X} -> 0x{target:08X} {strings[target]} ({kind}) {detail}")
 table=thumb_ins if mode=="THUMB" else None
 if table is not None:
  off=site-BASE
  for x in range(max(0,off-12),min(len(data)-3,off+20)+1,2):
   ii=table.get(x)
   if ii: ctx.append(f"  0x{BASE+x:08X}: {ii.mnemonic:8} {ii.op_str}")
out("xref_context.txt",ctx)
summary=[
 "Oppo A15 LK stage-4 targeted whole-image xref scan (READ ONLY)",
 f"image={IMAGE}",f"sha256={hashlib.sha256(raw).hexdigest()}",
 f"size={len(raw)} payload_offset=0x{PREFIX:X} load_base=0x{BASE:08X}",
 f"target_string_occurrences={len(strings)}",f"thumb_candidate_instructions={len(thumb_ins)}",
 f"exact_code_xrefs={len(set(hits))}",f"absolute_pointer_hits={len(pointer_hits)}",
 "Methods: exact ADR, literal-LDR + nearby ADD PC reconstruction, MOVW/MOVT, aligned absolute pointers.",
 "This is a targeted candidate scan, not proof of function boundaries; validate each xref context.",
 "No image bytes are modified. Do not flash any output from this analysis."
]
(OUT/"SUMMARY.txt").write_text("\n".join(summary)+"\n")
print("\n".join(summary))

# Trigger stage-4 targeted xref workflow.
