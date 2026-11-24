#!/usr/bin/env python3
"""Stage 8: trace callers of the unlock/lock confirmation routines.
Read-only analysis. Does not modify LK image.
"""
import os, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img"))
BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
PREFIX=int(os.getenv("PAYLOAD_OFFSET","0x200"),0)
raw=IMAGE.read_bytes(); data=raw[PREFIX:]
OUT=Path("menu-callers-stage8"); OUT.mkdir(exist_ok=True)
TARGETS={0x4802E960:"unlock_confirmation_flow",0x4802EA84:"lock_confirmation_flow",
         0x4802E5EC:"boot_mode_menu_renderer",0x4802E720:"unlock_prompt_renderer",
         0x4802E7B4:"lock_prompt_renderer"}
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def decode(p,n):
 return list(md.disasm(data[p:min(len(data),p+n)],BASE+p))
# Candidate Thumb direct call scan at halfword alignment; keep only BL/BLX to target.
hits=[]
for p in range(0,len(data)-4,2):
 for ins in md.disasm(data[p:p+4],BASE+p,count=1):
  if ins.mnemonic.lower() in ("bl","blx") and ins.operands and ins.operands[-1].type==2:
   t=ins.operands[-1].imm & 0xffffffff
   if t in TARGETS: hits.append((ins.address,t,ins.mnemonic,ins.op_str))
# For every candidate, collect surrounding instructions; preserve separate clusters.
for idx,(site,target,mn,op) in enumerate(hits,1):
 p=max(0,site-BASE-0x40); ins=decode(p,0xA0)
 lines=[f"CALLER CANDIDATE {idx}",f"site=0x{site:08X}",f"target={TARGETS[target]} 0x{target:08X}",f"instruction={mn} {op}",
        "Context:"]
 lines += [f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}" for i in ins]
 (OUT/f"caller_{idx:03d}.txt").write_text("\n".join(lines)+"\n")
# Focused full decode of surrounding code to inspect entry prologues and return paths.
for addr,label in [(0x4802E5EC,"menu_renderer"),(0x4802E960,"unlock_flow"),(0x4802EA84,"lock_flow"),(0x4802E830,"neighbor_function")]:
 p=addr-BASE
 ins=decode(p,0x240)
 (OUT/f"{label}_disassembly.txt").write_text("\n".join(f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}" for i in ins)+"\n")
summary=[
 "Oppo A15 LK Stage 8 - caller trace (read-only)",
 f"image={IMAGE}",f"sha256={hashlib.sha256(raw).hexdigest()}",
 f"size={len(raw)} payload_offset=0x{PREFIX:X} load_base=0x{BASE:08X}",
 f"candidate_calls_found={len(hits)}",
 "Targets:"
]+[f"0x{a:08X} {n}" for a,n in TARGETS.items()]
summary += ["", "Candidate call sites:"]+[f"0x{s:08X} -> 0x{t:08X} {TARGETS[t]} ({m} {o})" for s,t,m,o in hits]
summary += ["", "Caution: every-halfword Thumb decoding is candidate generation, not proof. Validate each call in a coherent CFG before patching.", "No LK bytes modified."]
(OUT/"SUMMARY.txt").write_text("\n".join(summary)+"\n")
print((OUT/"SUMMARY.txt").read_text())
