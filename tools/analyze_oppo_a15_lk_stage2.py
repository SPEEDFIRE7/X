#!/usr/bin/env python3
"""Second-stage, read-only ARM/Thumb reference analysis for Oppo A15 LK."""
import os, re, struct, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

img=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img"))
base=int(os.getenv("LOAD_BASE","0x48000000"),0)
prefix=int(os.getenv("PAYLOAD_OFFSET","0x200"),0)
out=Path("menu-xref-stage2"); out.mkdir(exist_ok=True)
b=img.read_bytes(); p=b[prefix:]
if len(p)<4: raise SystemExit("Invalid payload")
# Collect every printable string around the known menu and unlock area.
terms=[b"Select Boot Mode:",b"VOLUME_UP to select",b"Recovery    Mode",b"Fastboot    Mode",
       b"Unlock bootloader?",b"lock bootloader?",b"Volume UP/Down buttons",
       b"Yes (Volume Down):Unlock",b"No (Volume UP):Do not unlock bootloader."]
strings={}
for t in terms:
    q=p.find(t)
    if q>=0: strings[base+q]=t.decode()
targets=set(strings)
rows=[]
# Find all 32-bit occurrences, including unaligned words, of each string VA.
for va,s in strings.items():
    needle=struct.pack("<I",va)
    start=0
    while True:
        k=p.find(needle,start)
        if k<0: break
        rows.append(f"ABS_PTR string=0x{va:08X} ptr_va=0x{base+k:08X} file_off=0x{prefix+k:X} {s}")
        start=k+1
(out/"absolute_refs.txt").write_text("\n".join(rows) or "No absolute string pointers found.\n")

# Decode both modes. For PC-relative LDR, resolve the literal pool word;
# report both direct string pointers and pointers to pointer tables.
xrefs=[]; ldr_slots=set(); calls=[]
for name,mode,step in [("THUMB",CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN,2),("ARM",CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN,4)]:
    md=Cs(CS_ARCH_ARM,mode); md.detail=True
    for off in range(0,len(p)-4,step):
        va=base+off
        ins=next(md.disasm(p[off:off+4],va,count=1),None)
        if not ins: continue
        if ins.mnemonic in ("bl","blx","b","b.w","blx.w") and ins.operands and ins.operands[0].type==ARM_OP_IMM:
            dest=ins.operands[0].imm & 0xffffffff
            if base <= (dest & ~1) < base+len(p):
                calls.append((name,va,dest,ins.mnemonic,ins.op_str))
        dest=None; slot=None
        if ins.mnemonic.startswith("ldr") and len(ins.operands)>=2:
            op=ins.operands[1]
            if op.type==ARM_OP_MEM and op.mem.base==ARM_REG_PC:
                pc=((va+4)&~3) if name=="THUMB" else va+8
                slot=(pc+op.mem.disp)&0xffffffff
                idx=slot-base
                if 0<=idx<=len(p)-4:
                    dest=struct.unpack_from("<I",p,idx)[0]
                    ldr_slots.add(slot)
        elif ins.mnemonic=="adr" and len(ins.operands)>=2 and ins.operands[1].type==ARM_OP_IMM:
            dest=ins.operands[1].imm & 0xffffffff
        if dest in targets:
            xrefs.append(f"{name} DIRECT site=0x{va:08X} -> string=0x{dest:08X} {ins.mnemonic} {ins.op_str} [{ins.bytes.hex()}]")
        if slot is not None and dest is not None and base <= (dest & ~1) < base+len(p):
            # Candidate literal points to a structure/string area; retain for cross-reference.
            xrefs.append(f"{name} LITERAL site=0x{va:08X} slot=0x{slot:08X} value=0x{dest:08X} {ins.mnemonic} {ins.op_str}")
(out/"instruction_refs.txt").write_text("\n".join(xrefs) or "No resolvable references found.\n")

# Search instructions that materialize target addresses using MOVW/MOVT pairs.
movs=[]
for name,mode,step in [("THUMB",CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN,2),("ARM",CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN,4)]:
    md=Cs(CS_ARCH_ARM,mode); md.detail=True
    insns=[]
    for off in range(0,len(p)-4,step):
        ins=next(md.disasm(p[off:off+4],base+off,count=1),None)
        if ins: insns.append(ins)
    for i,ins in enumerate(insns):
        if ins.mnemonic not in ("movw","movt") or len(ins.operands)<2 or ins.operands[1].type!=ARM_OP_IMM: continue
        reg=ins.operands[0].reg; imm=ins.operands[1].imm & 0xffff
        if ins.mnemonic=="movw":
            for nxt in insns[i+1:i+7]:
                if nxt.mnemonic=="movt" and len(nxt.operands)>=2 and nxt.operands[0].reg==reg and nxt.operands[1].type==ARM_OP_IMM:
                    value=((nxt.operands[1].imm&0xffff)<<16)|imm
                    if value in targets:
                        movs.append(f"{name} MOVW/MOVT at 0x{ins.address:08X}/0x{nxt.address:08X} value=0x{value:08X} {strings[value]}")
                    break
(out/"movw_movt_refs.txt").write_text("\n".join(movs) or "No MOVW/MOVT address constructions for target strings found.\n")

# Emit compact code windows around xrefs and menu area. Mark likely prologues and calls.
windows=[]
for name,mode,step in [("THUMB",CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN,2),("ARM",CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN,4)]:
    md=Cs(CS_ARCH_ARM,mode)
    for anchor in [0x4808C33C,0x4808C484,0x4808C640]:
        start=max(0,anchor-base-0x300); end=min(len(p),anchor-base+0x300)
        windows.append(f"\n===== {name} around 0x{anchor:08X} =====")
        for ins in md.disasm(p[start:end],base+start):
            mark=""
            if ins.mnemonic in ("push","stmdb") and "lr" in ins.op_str: mark=" <POSSIBLE_PROLOGUE>"
            windows.append(f"0x{ins.address:08X}: {ins.mnemonic:8} {ins.op_str} [{ins.bytes.hex()}]{mark}")
(out/"menu_code_windows.txt").write_text("\n".join(windows))
(out/"call_targets.txt").write_text("\n".join(f"{m} {a:08X} {mn} -> {d:08X} {op}" for m,a,d,mn,op in calls[:10000]))
(out/"SUMMARY.txt").write_text(
    "Oppo A15 LK stage-2 static analysis (READ ONLY)\n"+
    f"image_sha256={hashlib.sha256(b).hexdigest()}\nsize={len(b)}\n"+
    f"menu_strings_found={len(strings)}\nabsolute_pointer_hits={len(rows)}\n"+
    f"instruction_reference_candidates={len(xrefs)}\nmovw_movt_string_refs={len(movs)}\n"+
    f"internal_branch_candidates={len(calls)}\n\n"+
    "Caution: linear sweeps may decode data as instructions. Candidate branch targets and prologues are not verified functions. No image is patched.\n")
print((out/"SUMMARY.txt").read_text())

# Stage-2 analyzer revision: re-run after workflow registration.\n