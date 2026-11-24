#!/usr/bin/env python3
"""Stage 15: precise menu call graph, pointer references, and menu text. READ ONLY."""
# Stage 15 workflow path fix applied.
import os, struct, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_INS_BL, ARM_INS_BLX, ARM_INS_B

IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img"))
BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
PREFIX=int(os.getenv("PAYLOAD_OFFSET","0x200"),0)
EXPECTED="b99a899639271f0494b5d4c4be05f99be54f7ecdfb5211b556895436e4803119"
raw=IMAGE.read_bytes(); payload=raw[PREFIX:]; sha=hashlib.sha256(raw).hexdigest()
OUT=Path("menu-trace-stage15"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
targets={
 0x48003F50:"boot_loop",0x480050D0:"time_delta_helper",0x480050E4:"delay_helper",
 0x4800512C:"config_loader",0x480052EC:"keycode_validator",
 0x48006F5C:"key_check_A",0x48006FA0:"key_check_B",
 0x4802E7EC:"menu_renderer",0x4802EB60:"menu_flow_A",0x4802EC84:"menu_flow_B",
 0x4802E920:"menu_setup_A",0x4802E9B4:"menu_setup_B",
 0x48026FBC:"display_helper",0x48032A78:"print_helper",
 0x480271E4:"menu_exit_helper",0x48027018:"menu_finish_helper"
}
def off(va): return va-BASE-PREFIX
def get(va,n):
 p=off(va); return payload[p:p+n] if p>=0 and p+n<=len(payload) else b""
def dis(va,n):
 return [f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}" for i in md.disasm(get(va,n),va)]
def save(name,lines): (OUT/name).write_text("\n".join(lines)+"\n")
# One sequential disassembly pass; retain exact direct control-flow xrefs.
xrefs={k:[] for k in targets}; caller_ins={}
for ins in md.disasm(payload,BASE+PREFIX):
 if ins.id in (ARM_INS_BL,ARM_INS_BLX,ARM_INS_B):
  try: dest=int(ins.op_str.split(",")[0].lstrip("#"),0)&~1
  except: continue
  if dest in xrefs:
   xrefs[dest].append(ins.address)
   caller_ins[ins.address]=f"0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}"
rows=["Direct Thumb branch/call xrefs from a single linear sweep (candidate sites; inspect CFG):"]
for dest,name in targets.items():
 rows.append(f"\n{name} 0x{dest:08X}: {len(xrefs[dest])}")
 for site in xrefs[dest][:300]: rows.append("  "+caller_ins[site])
save("DIRECT_XREFS.txt",rows)
# Context around every call to either menu flow, plus renderer and setup.
ctx=[]
for dest in (0x4802EB60,0x4802EC84,0x4802E7EC,0x4802E920,0x4802E9B4):
 ctx.append(f"\n=== {targets[dest]} 0x{dest:08X} ===")
 for site in xrefs[dest]:
  ctx.append(f"\n--- caller 0x{site:08X} ---")
  ctx.extend(dis(max(BASE+PREFIX,site-0x30),0x70))
save("MENU_CALLER_CONTEXT.txt",ctx)
# Full functions and adjacent strings/data.
funcs=[
 ("menu_flow_A.txt",0x4802EB60,0x110),("menu_flow_B.txt",0x4802EC84,0x110),
 ("menu_renderer.txt",0x4802E7EC,0x100),("boot_loop.txt",0x48003F50,0x230),
 ("menu_setup_A.txt",0x4802E920,0xA0),("menu_setup_B.txt",0x4802E9B4,0xA0),
 ("time_delta_helper.txt",0x480050D0,0x40),("key_check_A.txt",0x48006F5C,0x50),
 ("key_check_B.txt",0x48006FA0,0x50)]
for name,va,n in funcs: save(name,dis(va,n))
# Pointer words anywhere in payload that refer to function starts (Thumb bit allowed).
ptr=[]
for p in range(0,len(payload)-3,4):
 v=struct.unpack_from("<I",payload,p)[0]; dest=v&~1
 if dest in targets:
  ptr.append(f"file+0x{p+PREFIX:X} VA=0x{BASE+PREFIX+p:08X}: 0x{v:08X} -> {targets[dest]} 0x{dest:08X}")
save("FUNCTION_POINTER_REFS.txt",ptr or ["No aligned absolute pointer references found."])
# Extract printable strings near literal pools referenced by menu functions.
# Report all strings in a bounded data neighborhood around menu code and known string area.
strings=[]
for start,end in [(0x4802E700,0x4802EF80),(0x4808C200,0x4808C500)]:
 b=get(start,end-start); run=bytearray(); runstart=0
 for i,ch in enumerate(b+b"\x00"):
  if 32<=ch<127:
   if not run: runstart=i
   run.append(ch)
  else:
   if len(run)>=4:
    strings.append(f"0x{start+runstart:08X}: {run.decode('ascii','replace')}")
   run.clear()
save("MENU_STRINGS.txt",strings or ["No printable strings found in selected ranges."])
# Raw little-endian literal references within menu routines, to resolve PC-relative data.
lits=[]
for start,end in [(0x4802EB60,0x4802EE80),(0x4802E7EC,0x4802E96C),(0x48003F50,0x48004180)]:
 lits.append(f"\n--- {start:08X}..{end:08X} ---")
 for va in range(start,end-3,4):
  b=get(va,4)
  if len(b)==4:
   v=struct.unpack("<I",b)[0]
   if v>=0x48000000 or v<0x10000000: lits.append(f"0x{va:08X}: 0x{v:08X}")
save("MENU_LITERAL_WORDS.txt",lits)
summary=[
 "Stage 15 read-only call-graph and menu-string analysis.",
 f"image={IMAGE}",f"size={len(raw)}",f"sha256={sha}",f"expected_sha_match={sha==EXPECTED}",
 f"payload_offset=0x{PREFIX:X}; load_base=0x{BASE:08X}",
 f"linear_thumb_instructions={sum(1 for _ in md.disasm(payload,BASE+PREFIX))}",
 "Direct xrefs and pointer references are candidates; linear Thumb disassembly may cross data and must be checked against function boundaries.",
 "No LK image bytes modified."
]
save("SUMMARY.txt",summary); print("\n".join(summary))
