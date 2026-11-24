#!/usr/bin/env python3
"""Oppo A15 LK Stage 6: focused boot-menu function and caller analysis.
Read-only. Does not patch or rewrite the LK image.
"""
import os, struct, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_MODE_ARM

IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img"))
BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
PREFIX=int(os.getenv("PAYLOAD_OFFSET","0x200"),0)
raw=IMAGE.read_bytes(); data=raw[PREFIX:]
OUT=Path("menu-xref-stage6"); OUT.mkdir(exist_ok=True)
TARGETS=[0x48032878,0x480328A0,0x480328DC,0x4802E602,0x4802E736,0x4802E7CA]
# Relevant window containing the menu and adjacent unlock/lock confirmation logic.
WINDOWS=[(0x4802E560,0x4802E860),(0x48032840,0x48032920)]
tm=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); tm.detail=True
am=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); am.detail=True

def off(va): return va-BASE
def in_image(va): return 0 <= off(va) < len(data)
def decode_window(md, start, end):
    a=max(0,off(start)); b=min(len(data),off(end))
    return list(md.disasm(data[a:b],BASE+a))
def dump_insns(label, insns):
    lines=[f"## {label}"]
    for i in insns:
        lines.append(f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}")
    return lines
# Focused disassembly in both states around the known menu strings and print helper.
thumb_windows=[]
arm_windows=[]
for a,b in WINDOWS:
    thumb_windows += decode_window(tm,a,b)
    arm_windows += decode_window(am,a,b)
# Search aligned Thumb halfwords and ARM words for direct calls/branches to key helpers.
# Decode from every aligned offset independently; this is a candidate scan, not CFG proof.
def candidate_calls(md, step, mode):
    found=[]
    for p in range(0,len(data)-4,step):
        for ins in md.disasm(data[p:p+4],BASE+p,count=1):
            if ins.mnemonic.lower().startswith(("bl","blx","b")) and ins.operands:
                op=ins.operands[-1]
                if getattr(op,"type",0)==2 and (op.imm & 0xFFFFFFFF) in TARGETS:
                    found.append((mode,ins.address,ins.mnemonic,ins.op_str,op.imm & 0xFFFFFFFF))
    return found
calls=candidate_calls(tm,2,"THUMB")+candidate_calls(am,4,"ARM")
# Direct calls/branches inside menu region, plus the full decoded region.
menu_calls=[]
for i in thumb_windows+arm_windows:
    m=i.mnemonic.lower()
    if m.startswith(("bl","blx","b")) and i.operands and getattr(i.operands[-1],"type",0)==2:
        menu_calls.append((i.address,m,i.op_str,i.operands[-1].imm & 0xFFFFFFFF))
# String bytes around the menu for exact verification.
needles=[b"Select Boot Mode:",b"VOLUME_UP to select",b"Recovery    Mode",b"Fastboot    Mode",b"Normal      Boot",b"Unlock bootloader?",b"lock bootloader?",b"Yes (Volume Down):Unlock",b"No (Volume UP):Do not unlock bootloader."]
string_lines=[]
for needle in needles:
    pos=0
    while True:
        pos=data.find(needle,pos)
        if pos<0: break
        string_lines.append(f"0x{BASE+pos:08X} {needle.decode('ascii')}")
        pos+=1
# Thumb instructions are authoritative candidate state based on Stage 5 xrefs.
# Include a compact focused dump and references into menu's nearby routines.
def write(name, lines):
    (OUT/name).write_text("\n".join(lines)+"\n")
write("SUMMARY.txt",[
 "Oppo A15 LK Stage 6 focused analysis (READ ONLY)",
 f"image={IMAGE}",f"sha256={hashlib.sha256(raw).hexdigest()}",
 f"size={len(raw)} payload_offset=0x{PREFIX:X} load_base=0x{BASE:08X}",
 "Known string xrefs: THUMB 0x4802E602 -> Select Boot Mode; 0x4802E736 -> Unlock prompt; 0x4802E7CA -> Lock prompt.",
 "Known print-helper call target: 0x48032878 (called repeatedly after LDR+ADD-PC string address construction).",
 f"aligned_candidate_direct_calls_to_targets={len(calls)}",
 f"focused_window_instructions_thumb={len(thumb_windows)} arm={len(arm_windows)}",
 "This scan reports candidate branch targets; data regions can decode as instructions. Confirm function boundaries and call sites before patching.",
 "No image bytes modified."
])
write("menu_region_thumb.txt",dump_insns("THUMB menu/unlock/lock region",thumb_windows))
write("menu_region_arm.txt",dump_insns("ARM decode of same regions (comparison only)",arm_windows))
write("helper_callers.txt",[f"{mode} 0x{site:08X}: {mn} {op} -> 0x{target:08X}" for mode,site,mn,op,target in sorted(set(calls))])
write("menu_region_branches.txt",[f"0x{site:08X}: {mn} {op} -> 0x{target:08X}" for site,mn,op,target in sorted(set(menu_calls))])
write("menu_strings.txt",sorted(set(string_lines)))
print((OUT/"SUMMARY.txt").read_text())
