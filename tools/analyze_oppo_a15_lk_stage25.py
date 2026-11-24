#!/usr/bin/env python3
"""Stage 25: identify real boot-mode menu owner and global indirect dispatch. READ ONLY."""
import os,struct,hashlib,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage25"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def get(va,n):
 p=va-BASE; return raw[p:p+n] if p>=0 and p+n<=len(raw) else b""
def dis(va,n): return list(md.disasm(get(va,n),va))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
# This is the code immediately following the unlock/lock prompt setup.
regions=[("post_lock_flow_2EA30.txt",0x4802EA30,0x130),
("bootmode_renderer_2E7EC.txt",0x4802E7EC,0x100),
("unlock_flow_2EB60.txt",0x4802EB60,0x110),
("lock_flow_2EC84.txt",0x4802EC84,0x110),
("boot_main_03100.txt",0x48003100,0x180),
("boot_loop_03F50.txt",0x48003F50,0x240)]
for n,va,sz in regions: save(n,[fmt(i) for i in dis(va,sz)])
# Full-image sweep to locate register-indirect calls/jumps and table branches.
ind=[]; tables=[]
for ins in md.disasm(raw,BASE):
 if ins.mnemonic in ("blx","bx") and ins.op_str and not ins.op_str.startswith("#") and ins.op_str.strip() not in ("lr","r14"):
  ind.append(fmt(ins))
 if ins.mnemonic in ("tbb","tbh"):
  tables.append(fmt(ins))
 if ins.mnemonic in ("ldr","ldm","pop") and "pc" in ins.op_str:
  tables.append(fmt(ins))
save("GLOBAL_INDIRECT_DISPATCH.txt",ind)
save("GLOBAL_PC_LOADS_AND_TABLE_BRANCHES.txt",tables)
# Resolve PIC strings from the newly discovered 2EA30 block.
strings=[]
ins=dis(0x4802EA30,0x130)
for j,x in enumerate(ins):
 m=re.search(r"\[pc,\s*#(0x[0-9a-fA-F]+|\d+)\]",x.op_str)
 if not m: continue
 lit=((x.address+4)&~3)+int(m.group(1),0); w=get(lit,4)
 if len(w)!=4: continue
 val=struct.unpack("<I",w)[0]
 for y in ins[j+1:j+4]:
  if y.mnemonic=="add" and ", pc" in y.op_str:
   target=(val+y.address+4)&0xffffffff; b=get(target,160); s=b.split(b"\0",1)[0]
   strings.append(f"LDR@0x{x.address:08X} literal@0x{lit:08X}=0x{val:08X}; ADD@0x{y.address:08X}; target=0x{target:08X}: {s.decode('ascii','replace') if s and all(31<c<127 for c in s) else b[:48].hex(' ')}")
   break
save("POST_LOCK_FLOW_STRINGS.txt",strings)
summary=["Stage 25 read-only boot-mode owner and global indirect-dispatch scan.",f"image={IMAGE}",f"size={len(raw)}",f"sha256={hashlib.sha256(raw).hexdigest()}",f"global_register_indirect_sites={len(ind)}",f"global_pc_load_or_table_branch_sites={len(tables)}","No LK image bytes modified."]
save("SUMMARY.txt",summary); print("\n".join(summary))
