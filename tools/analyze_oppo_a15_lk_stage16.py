#!/usr/bin/env python3
"""Stage 16: trace boot-loop caller, indirect menu references, and menu string literals. READ ONLY."""
import os,struct,hashlib,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); sha=hashlib.sha256(raw).hexdigest(); OUT=Path("menu-trace-stage16"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
regions=[("boot_loop_caller_03140.txt",0x48003140,0x140),("boot_loop_03F50.txt",0x48003F50,0x230),
("menu_A_02EB60.txt",0x4802EB60,0x110),("menu_B_02EC84.txt",0x4802EC84,0x110),
("renderer_02E7EC.txt",0x4802E7EC,0x100),("setup_A_02E920.txt",0x4802E920,0x90),("setup_B_02E9B4.txt",0x4802E9B4,0x90)]
for name,va,n in regions: save(name,[fmt(i) for i in dis(va,n)])
litrows=[]; strrows=[]
for name,va,n in regions[2:]:
 ins=dis(va,n)
 for j,x in enumerate(ins):
  if not x.mnemonic.startswith("ldr") or "[pc" not in x.op_str: continue
  m=re.search(r"\[pc,\s*#(0x[0-9a-fA-F]+|\d+)\]",x.op_str)
  if not m: continue
  lva=((x.address+4)&~3)+int(m.group(1),0); w=get(lva,4)
  if len(w)!=4: continue
  v=struct.unpack("<I",w)[0]; litrows.append(f"{name}: {fmt(x)} literal@0x{lva:08X}=0x{v:08X}")
  if j+1<len(ins) and ins[j+1].mnemonic=="add" and ", pc" in ins[j+1].op_str:
   target=(v+ins[j+1].address+4)&0xFFFFFFFF; b=get(target,160); s=b.split(b"\0",1)[0]
   if s and all(31<c<127 for c in s): strrows.append(f"{name}: target 0x{target:08X}: {s.decode('ascii','replace')}")
save("MENU_LITERALS_RESOLVED.txt",litrows); save("MENU_REFERENCED_STRINGS.txt",strrows)
targets={0x4802EB60:"menu_A",0x4802EC84:"menu_B",0x4802E7EC:"renderer",0x48003F50:"boot_loop"}
hits=[]
for p in range(0,len(raw)-3):
 v=struct.unpack_from("<I",raw,p)[0]; d=v&~1
 if d in targets: hits.append(f"file+0x{p:08X} VA=0x{BASE+p:08X}: 0x{v:08X} -> {targets[d]}")
save("BYTEWISE_FUNCTION_POINTER_REFS.txt",hits or ["No byte-aligned absolute pointer references found."])
caller=[]
for va in (0x4800319A,0x480040BC,0x480040DA,0x4802EB76,0x4802ECA8):
 caller.append(f"\n--- around 0x{va:08X} ---"); caller.extend(fmt(i) for i in dis(va-0x30,0x80))
save("CALLER_WINDOWS.txt",caller)
summary=["Stage 16 read-only targeted trace.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={sha}",f"expected_sha_match={sha=='b99a899639271f0494b5d4c4be05f99be54f7ecdfb5211b556895436e4803119'}","Resolves PC-relative literal references in menu routines and searches bytewise function pointers.","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))
