#!/usr/bin/env python3
"""Stage 42: trace device-tree keypad property loading and key-code defaults. READ ONLY."""
import os,struct,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
IMAGE=Path(os.getenv("IMAGE_PATH","oppo-a15-signed-test.img")); BASE=int(os.getenv("LOAD_BASE","0x48000000"),0)
raw=IMAGE.read_bytes(); OUT=Path("menu-trace-stage42"); OUT.mkdir(exist_ok=True)
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
def get(a,n):
 p=a-BASE
 return raw[p:p+n] if 0<=p and p+n<=len(raw) else b""
def dis(a,n): return list(md.disasm(get(a,n),a))
def fmt(i): return f"0x{i.address:08X}: {i.mnemonic:9} {i.op_str}"
def save(n,ls): (OUT/n).write_text("\n".join(ls)+"\n")
sha=hashlib.sha256(raw).hexdigest()
save("IMAGE_ID.txt",[f"size={len(raw)}",f"sha256={sha}","READ ONLY"])
regions=[
 ("key_config_loader_0512C.txt",0x4800512C,0x360),
 ("key_validator_052EC.txt",0x480052EC,0x180),
 ("pmic_key_getters_06F5C_06FA0.txt",0x48006F5C,0x100),
 ("dt_property_helpers_33E50_33F20.txt",0x48033E50,0xD0),
 ("dt_property_helpers_33C00_33D20.txt",0x48033C00,0x120),
 ("key_map_helper_0610C_06140.txt",0x4800610C,0x70),
]
for n,a,z in regions: save(n,[fmt(i) for i in dis(a,z)])
props=[
 b"mediatek,kpd-sw-pwrkey",b"mediatek,kpd-hw-pwrkey",
 b"mediatek,kpd-sw-rstkey",b"mediatek,kpd-hw-rstkey",
 b"mediatek,kpd-use-extend-type",b"mediatek,kpd-hw-recovery-key",
 b"mediatek,kpd-hw-factory-key",b"mediatek,kpd-hw-map-num"
]
hits=[]
for s in props:
 p=0
 while True:
  p=raw.find(s,p)
  if p<0: break
  lo=max(0,p-32); hi=min(len(raw),p+len(s)+64)
  hits.append(f"property={s.decode()} file+0x{p:X} VA=0x{BASE+p:08X}\n  bytes[{lo:X}:{hi:X}]={raw[lo:hi].hex(' ')}")
  p+=1
save("KEY_PROPERTY_RAW_CONTEXT.txt",hits)
# Find key names as ASCII strings and their offsets.
strings=[]
for s in props:
 p=raw.find(s)
 if p>=0: strings.append(f"0x{BASE+p:08X}: {s.decode()}")
save("KEY_PROPERTY_OFFSETS.txt",strings)
# Report known code locations and default constants as hypotheses to verify.
save("KEY_CONFIG_NOTES.txt",[
 "Loader function: 0x4800512C (see disassembly).",
 "Validator function: 0x480052EC; it accepts a key code and calls PMIC-level key checks.",
 "Known struct offsets from previous static trace: +0x138 = mediatek,kpd-hw-recovery-key; +0x13C = mediatek,kpd-hw-factory-key.",
 "Default fallback previously observed when DT keypad properties are absent: +4=8, +0xC=17, +0x138=17, +0x13C=0-like null value.",
 "These fallback values are not proof of Volume Up/Down identity; actual device-tree property data must be resolved."
])
save("SUMMARY.txt",[
 "Stage 42 completed: read-only keypad DT loader and validator trace.",
 f"image_size={len(raw)}",f"sha256={sha}",
 f"property_contexts={len(hits)}",
 "No physical key is labelled Volume Up/Down without matching actual device-tree value and hardware evidence.",
 "No LK image bytes modified."
])
print("\n".join(["Stage 42 complete",f"sha256={sha}",f"property_contexts={len(hits)}"]))

# Trigger after workflow registration.
