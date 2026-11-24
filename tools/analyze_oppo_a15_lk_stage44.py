#!/usr/bin/env python3
"""Stage 44: decode PMIC key readers and DT node lookup entrypoints. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage44"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(a,n):
 p=a-BASE
 return raw[p:p+n] if 0<=p and p+n<=len(raw) else b""
def dis(a,n): return list(md.disasm(get(a,n),a))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
def dump(a,n):
 b=get(a,n); z=[f"base=0x{a:08X} size=0x{len(b):X}"]
 for o in range(0,len(b)-3,4): z.append(f"+0x{o:03X} @0x{a+o:08X}: 0x{struct.unpack_from('<I',b,o)[0]:08X}")
 return z
sha=hashlib.sha256(raw).hexdigest()
save("IMAGE_ID.txt",[f"size={len(raw)}",f"sha256={sha}","READ ONLY"])
regions=[
 ("key_reader_06F5C.txt",0x48006F5C,0xC0),
 ("key_reader_06FA0.txt",0x48006FA0,0xC0),
 ("pmic_read_wrapper_0610C.txt",0x4800610C,0x90),
 ("pmic_bus_read_05618.txt",0x48005618,0x100),
 ("dt_node_lookup_32E4C.txt",0x48032E4C,0x120),
 ("dt_node_path_43708.txt",0x48043708,0x100),
 ("dt_lookup_string_helpers_33E50.txt",0x48033E50,0x100),
]
for n,a,z in regions: save(n,[fmt(i) for i in dis(a,z)])
for n,a,z in [
 ("key_reader_literals_06F00.txt",0x48006F00,0x100),
 ("dt_node_literals_43700.txt",0x48043700,0x60),
 ("dt_lookup_literals_32E00.txt",0x48032E00,0x80),
 ("kpd_mmio_map.txt",0x48000000,0x20)
]: save(n,dump(a,z))
# Report exact references to key property strings and node path.
terms=[b"/kp@10010000",b"mediatek,kpd-hw-pwrkey",b"mediatek,kpd-hw-rstkey",
       b"mediatek,kpd-hw-recovery-key",b"mediatek,kpd-hw-factory-key"]
hits=[]
for s in terms:
 p=0
 while True:
  p=raw.find(s,p)
  if p<0: break
  hits.append(f"VA=0x{BASE+p:08X} {s.decode(errors='replace')}")
  p+=1
save("KEY_DT_STRINGS.txt",hits)
save("SUMMARY.txt",[
 "Stage 44 decoded the direct PMIC key readers and DT node lookup entrypoints.",
 f"image_size={len(raw)}",f"sha256={sha}",
 "Key reader return values are interpreted only as pressed/not-pressed where the code proves that behavior.",
 "The 0x10010000 keypad register/map path is treated as MMIO, not static image bytes.",
 "No LK image bytes modified."
])
print("\n".join(["Stage 44 complete",f"sha256={sha}"]))
