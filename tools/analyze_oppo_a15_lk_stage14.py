#!/usr/bin/env python3
"""Stage 14: trace LK key acquisition, key filters, and boot-menu entry. READ ONLY."""
import os, struct, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

IMAGE = Path(os.getenv("IMAGE_PATH", "oppo-a15-signed-test.img"))
BASE = int(os.getenv("LOAD_BASE", "0x48000000"), 0)
PREFIX = int(os.getenv("PAYLOAD_OFFSET", "0x200"), 0)
EXPECTED = "b99a899639271f0494b5d4c4be05f99be54f7ecdfb5211b556895436e4803119"
raw = IMAGE.read_bytes()
payload = raw[PREFIX:]
sha = hashlib.sha256(raw).hexdigest()
OUT = Path("menu-trace-stage14"); OUT.mkdir(exist_ok=True)

thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); thumb.detail = True
arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN); arm.detail = True

def offset(va): return va - BASE - PREFIX
def get(va, n):
    p = offset(va)
    return payload[p:p+n] if p >= 0 and p+n <= len(payload) else b""
def dis(va, n, md):
    b = get(va,n)
    return [f"0x{i.address:08X}: {i.mnemonic:10} {i.op_str}" for i in md.disasm(b,va)]
def dump(va,n):
    b=get(va,n); return [f"0x{va+i:08X}: "+" ".join(f"{x:02X}" for x in b[i:i+16]) for i in range(0,len(b),16)]
def save(name, lines): (OUT/name).write_text("\n".join(lines)+"\n")

# Key acquisition and key-code validation routines established by Stage 13.
regions = [
 ("key_getter_050D0_thumb.txt",0x48005080,0x180,thumb),
 ("key_getter_050D0_arm.txt",0x48005080,0x180,arm),
 ("key_delay_050E4_thumb.txt",0x480050C0,0x140,thumb),
 ("key_config_0512C_thumb.txt",0x48005100,0x180,thumb),
 ("key_filter_052EC_thumb.txt",0x480052EC,0x100,thumb),
 ("key_check_06F5C_thumb.txt",0x48006F20,0x100,thumb),
 ("key_check_06FA0_thumb.txt",0x48006F70,0x100,thumb),
 ("key_check_06F5C_arm.txt",0x48006F20,0x100,arm),
 ("key_check_06FA0_arm.txt",0x48006F70,0x100,arm),
 ("boot_loop_03F6C_thumb.txt",0x48003F40,0x280,thumb),
 ("menu_flow_02EB60_thumb.txt",0x4802EB40,0x220,thumb),
 ("menu_flow_02EC84_thumb.txt",0x4802EC60,0x220,thumb),
 ("menu_renderer_02E7EC_thumb.txt",0x4802E7C0,0x180,thumb),
]
for name,va,n,md in regions: save(name,dis(va,n,md))

# Full raw windows preserve evidence when overlapping disassembly includes data.
save("KEY_ROUTINES_RAW.txt",[
 "--- getter / delay / config ---",*dump(0x48005080,0x280),
 "--- filter and helper routines ---",*dump(0x480052EC,0x100),
 "--- hardware check candidates ---",*dump(0x48006F20,0x100),
 "--- main loop ---",*dump(0x48003F40,0x280)
])

# Literal pools near routines, both aligned words and nearby absolute pointers.
lits=[]
for start,end in [(0x48005080,0x48005280),(0x480052EC,0x48005390),(0x48006F20,0x48007020),(0x4802EB40,0x4802EE80)]:
    lits.append(f"--- {start:08X}..{end:08X} ---")
    for va in range(start,end-3,4):
        b=get(va,4)
        if len(b)==4:
            v=struct.unpack("<I",b)[0]
            if v >= 0x48000000 or v < 0x10000000:
                lits.append(f"0x{va:08X}: 0x{v:08X}")
save("LITERAL_WORD_CANDIDATES.txt",lits)

# Search halfword-aligned Thumb BL candidates across payload for calls into
# known input, validation, and menu functions. Each is a candidate; nearby
# disassembly is emitted for manual CFG verification.
targets={0x480050D0:"key_getter",0x480050E4:"key_delay",0x4800512C:"key_config",
         0x480052EC:"key_validator",0x48006F5C:"key_check_A",0x48006FA0:"key_check_B",
         0x4802E7EC:"menu_renderer",0x4802EB60:"menu_flow_A",0x4802EC84:"menu_flow_B"}
hits={k:[] for k in targets}
for p in range(0,len(payload)-4,2):
    va=BASE+PREFIX+p
    for ins in thumb.disasm(payload[p:p+4],va):
        if ins.mnemonic == "bl":
            try: dest=int(ins.op_str.lstrip("#"),0)
            except: continue
            if dest in hits: hits[dest].append(va)
            break
rows=[]
for dest,name in targets.items():
    rows.append(f"{name} 0x{dest:08X}: {len(hits[dest])} candidate BL sites")
    for site in hits[dest][:160]:
        rows.append(f"  caller 0x{site:08X}")
save("CALLER_CANDIDATES.txt",rows)

# Extract coherent local context around calls from main boot loop and menu code.
contexts=[]
for dest in targets:
    for site in hits[dest]:
        if 0x48003E00 <= site <= 0x48004250 or 0x4802EA00 <= site <= 0x4802EF00:
            contexts.append(f"--- callsite 0x{site:08X} -> 0x{dest:08X} ---")
            contexts.extend(dis(max(BASE+PREFIX,site-0x20),0x60,thumb))
save("RELEVANT_CALLSITE_CONTEXT.txt",contexts or ["No candidate call sites in the selected boot/menu windows."])

summary=[
"Stage 14 read-only trace of key acquisition and menu entry paths.",
f"image={IMAGE}",f"size={len(raw)}",f"sha256={sha}",f"expected_sha_match={sha==EXPECTED}",
f"payload_offset=0x{PREFIX:X}; load_base=0x{BASE:08X}",
"Stage 13 showed the boot loop calls 0x480050D0, then compares its return value and passes [r6+0x138] to 0x480052EC.",
"Stage 14 disassembles key getter 0x480050D0, delay/helper 0x480050E4, config accessor 0x4800512C, validators 0x48006F5C/0x48006FA0, menu loops, and renderer.",
"CALLER_CANDIDATES are linear Thumb scans and must be validated against coherent function boundaries/control flow.",
"No LK image bytes modified."
]
save("SUMMARY.txt",summary)
print("\n".join(summary))
