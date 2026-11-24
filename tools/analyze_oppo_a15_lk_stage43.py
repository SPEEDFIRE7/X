#!/usr/bin/env python3
"""Stage 43: inspect DT lookup/value helpers used by the keypad loader. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage43"); OUT.mkdir(exist_ok=True)
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
 ("dt_handle_helper_43708.txt",0x48043708,0x180),
 ("dt_find_property_34A40.txt",0x48034A40,0x1A0),
 ("dt_value_read_050EC.txt",0x480050EC,0x100),
 ("dt_property_copy_3494C.txt",0x4803494C,0x140),
 ("dt_blob_init_33C2C.txt",0x48033C2C,0x100),
 ("key_loader_0512C_again.txt",0x4800512C,0x1A0),
]
for n,a,z in regions: save(n,[fmt(i) for i in dis(a,z)])
# Loader literal pool; derive all names/strings and pointer candidates.
for n,a,z in [
 ("key_loader_literals_5280.txt",0x48005280,0x80),
 ("dt_global_candidates_483C5700.txt",0x483C5700,0x200),
 ("dt_global_candidates_483C8900.txt",0x483C8900,0x200),
]: save(n,dump(a,z))
# All exact strings that look like property lookup/debug traces.
needles=[b"keypad dts not found",b"kpd_sw_pwrkey",b"kpd_hw_pwrkey",
 b"kpd_sw_rstkey",b"kpd_hw_rstkey",b"recovery_key =",b"factory_key =",
 b"mediatek,kpd-hw-recovery-key",b"mediatek,kpd-hw-factory-key"]
hits=[]
for s in needles:
 p=0
 while True:
  p=raw.find(s,p)
  if p<0: break
  hits.append(f"VA=0x{BASE+p:08X} file+0x{p:X}: {raw[p:p+120].split(bytes([0]),1)[0]!r}")
  p+=1
save("DT_KEY_DEBUG_STRINGS.txt",hits)
save("SUMMARY.txt",[
 "Stage 43 inspected the exact DT handle, property lookup, and value conversion helpers.",
 f"image_size={len(raw)}",f"sha256={sha}",
 "This stage distinguishes property-name strings from actual runtime device-tree property values.",
 "If the DT handle is runtime-provided, its numeric key properties cannot be recovered from string offsets alone.",
 "No LK image bytes modified."
])
print("\n".join(["Stage 43 complete",f"sha256={sha}"]))
