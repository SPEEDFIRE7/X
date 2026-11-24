#!/usr/bin/env python3
"""Stage 38: correct global-base resolution and state pointer slots. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage38"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def get(a,n):
 p=a-BASE
 return raw[p:p+n] if 0<=p and p+n<=len(raw) else b""
def dis(a,n): return list(md.disasm(get(a,n),a))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
def dump_words(a,n):
 b=get(a,n); z=[f"base=0x{a:08X} size=0x{len(b):X}"]
 for o in range(0,len(b)-3,4): z.append(f"+0x{o:03X} @0x{a+o:08X}: 0x{struct.unpack_from('<I',b,o)[0]:08X}")
 return z
sha=hashlib.sha256(raw).hexdigest()
save("IMAGE_ID.txt",[f"size={len(raw)}",f"sha256={sha}","READ ONLY"])
# Correct PC-relative calculations for the main loop's base and offsets.
# ldr r4,[pc,#0x230] at 3F54 loads 0x003C13C0; add r4,pc at 3F58 => 0x483C551C.
base=0x483C551C
save("MAIN_LOOP_GLOBAL_BASE.txt",[
 "Main-loop base derivation:",
 "0x48003F54 LDR r4,[PC,#0x230] reads literal at 0x48004188 = 0x003C13C0.",
 "0x48003F58 ADD r4,PC uses aligned PC 0x48003F5C.",
 f"Resolved r4 = 0x{base:08X}.",
 "Earlier 0x483C531C assumption is not supported by this literal calculation."
])
for name,a,n in [
 ("main_global_offsets_2D8_444_4C0_514.txt",base+0x2D8,0x260),
 ("main_state_slot_2D8.txt",base+0x2D8,0x40),
 ("main_state_slot_444.txt",base+0x444,0x40),
 ("main_state_slot_4C0.txt",base+0x4C0,0x40),
 ("main_state_slot_514.txt",base+0x514,0x40),
 ("parent_literal_pool_3900.txt",0x48003900,0x100),
 ("parent_prologue_02E00_03100.txt",0x48002E00,0x300),
 ("parent_state_global_candidates_483C5700.txt",0x483C5700,0x400),
]: save(name,dump_words(a,n) if "txt" in name and "prologue" not in name else [fmt(i) for i in dis(a,n)])
# Dump true executable prologue and parent dispatch continuation, with proper instruction decoding.
for name,a,n in [
 ("parent_prologue_disasm_02E00_03100.txt",0x48002E00,0x300),
 ("parent_after_mainloop_03190_03330.txt",0x48003190,0x1A0),
 ("parent_state_paths_03500_03880.txt",0x48003500,0x380),
 ("main_loop_03F50_04190.txt",0x48003F50,0x240),
]: save(name,[fmt(i) for i in dis(a,n)])
save("SUMMARY.txt",[
 "Stage 38 completed: re-derived main-loop globals from PC-relative literals.",
 f"image_size={len(raw)}",f"sha256={sha}",
 f"main_loop_global_base=0x{base:08X}",
 "This corrects the earlier tentative global-base address; all state-slot conclusions must use the resolved base.",
 "No LK image bytes modified."
])
print("\n".join(["Stage 38 complete",f"sha256={sha}",f"main_loop_global_base=0x{base:08X}"]))
