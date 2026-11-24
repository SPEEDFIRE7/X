#!/usr/bin/env python3
"""Stage 7: find and contextualize callers of Oppo A15 LK boot-menu routines.
READ ONLY: never changes the LK image.
"""
import os, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img"))
BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
PREFIX=int(os.getenv("PAYLOAD_OFFSET","0x200"),0)
raw=IMAGE.read_bytes(); data=raw[PREFIX:]
OUT=Path("menu-callers-stage7"); OUT.mkdir(exist_ok=True)
# Functions identified by direct instruction sequences in Stage 6.
TARGETS={
 0x4802E5EC:"boot_mode_menu_text_renderer",
 0x4802E720:"unlock_confirmation_text_renderer",
 0x4802E7B4:"lock_confirmation_text_renderer",
 0x4802E644:"separate_helper_near_menu_not_yet_classified",
}
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def decode_at(p,n=0x60):
 return list(md.disasm(data[p:min(len(data),p+n)],BASE+p))
# Candidate call-site scan. Thumb BL/BLX instructions are decoded at every halfword
# alignment, then only direct immediate targets matching known routines are retained.
candidates=[]
for p in range(0,len(data)-4,2):
 for ins in md.disasm(data[p:p+4],BASE+p,count=1):
  if ins.mnemonic.lower() in ("bl","blx") and ins.operands and ins.operands[-1].type==2:
   target=ins.operands[-1].imm & 0xffffffff
   if target in TARGETS:
    candidates.append((ins.address,target,ins.mnemonic,ins.op_str))
# Merge nearby candidates into caller clusters; surrounding bytes are decoded for context.
clusters=[]
for site,target,mn,op in sorted(candidates):
 if clusters and site-clusters[-1][-1][0] <= 0x80:
  clusters[-1].append((site,target,mn,op))
 else: clusters.append([(site,target,mn,op)])
lines=[
 "Oppo A15 LK Stage 7 - caller tracing (candidate scan; read only)",
 f"image={IMAGE}",f"sha256={hashlib.sha256(raw).hexdigest()}",
 f"size={len(raw)} payload_offset=0x{PREFIX:X} load_base=0x{BASE:08X}",
 "Targets:"
]
for a,n in TARGETS.items(): lines.append(f"  0x{a:08X} {n}")
lines += [f"candidate_direct_call_sites={len(candidates)}",f"caller_clusters={len(clusters)}",
 "WARNING: every-halfword Thumb decoding can yield false positives in embedded data. A caller is not confirmed until instruction alignment and function CFG are validated."]
(OUT/"SUMMARY.txt").write_text("\n".join(lines)+"\n")
for idx,cluster in enumerate(clusters,1):
 start=max(0,cluster[0][0]-0x30-BASE); end=min(len(data),cluster[-1][0]+0x60-BASE)
 insns=list(md.disasm(data[start:end],BASE+start))
 out=[f"Cluster {idx}: {cluster[0][0]:08X}..{cluster[-1][0]:08X}"]
 for site,target,mn,op in cluster: out.append(f"CALLSITE 0x{site:08X}: {mn} {op} -> {TARGETS[target]} (0x{target:08X})")
 out += [f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}" for i in insns]
 (OUT/f"cluster_{idx:02d}.txt").write_text("\n".join(out)+"\n")
print((OUT/"SUMMARY.txt").read_text())
