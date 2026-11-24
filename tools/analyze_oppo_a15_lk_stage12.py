#!/usr/bin/env python3
"""Stage 12: focused LK menu caller/key-dispatch trace. READ ONLY; never patches image."""
import os, struct, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

img = Path(os.getenv("IMAGE_PATH", "oppo-a15-signed-test.img"))
base = int(os.getenv("LOAD_BASE", "0x48000000"), 0)
prefix = int(os.getenv("PAYLOAD_OFFSET", "0x200"), 0)
raw = img.read_bytes()
payload = raw[prefix:]
sha = hashlib.sha256(raw).hexdigest()
expected = "b99a899639271f0494b5d4c4be05f99be54f7ecdfb5211b556895436e4803119"
out = Path("menu-trace-stage12")
out.mkdir(exist_ok=True)

def off(va): return va - base - prefix
def dis(va, size, md):
    p = off(va)
    if p < 0 or p >= len(payload): return [f"OUTSIDE: 0x{va:08X}"]
    return [f"0x{i.address:08X}: {i.mnemonic:10} {i.op_str}" for i in md.disasm(payload[p:p+size], va)]
def hexdump(va, size):
    p=off(va)
    if p<0 or p>=len(payload): return [f"OUTSIDE: 0x{va:08X}"]
    return [f"0x{base+prefix+q:08X}: "+" ".join(f"{x:02X}" for x in payload[q:min(q+16,p+size)]) for q in range(p,min(len(payload),p+size),16)]

thumb=Cs(CS_ARCH_ARM, CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); thumb.detail=True
arm=Cs(CS_ARCH_ARM, CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); arm.detail=True

# Stage 11 identified two coherent loops around these addresses. The ranges deliberately
# include their setup, key tests, renderer calls, and return/dispatch tails.
ranges = [
    ("menu_key_loop_A_thumb.txt",0x4802EB60,0x180,thumb),
    ("menu_key_loop_B_thumb.txt",0x4802EC84,0x1C0,thumb),
    ("menu_helpers_thumb.txt",0x4802E840,0x1A0,thumb),
    ("key_dispatch_thumb.txt",0x48005200,0x500,thumb),
    ("key_dispatch_arm.txt",0x48005200,0x500,arm),
    ("menu_key_loop_A_arm.txt",0x4802EB60,0x180,arm),
    ("menu_key_loop_B_arm.txt",0x4802EC84,0x1C0,arm),
]
for name,va,size,md in ranges:
    (out/name).write_text("\n".join(dis(va,size,md))+"\n")

# Dump literal pools/data referenced near the menu loops for resolving key labels and IDs.
literal=[]
for start,end in [(0x4802EC40,0x4802EC84),(0x4802ED80,0x4802EE20),(0x48005200,0x48005280)]:
    literal += [f"--- {start:08X}-{end:08X} ---"]
    for va in range(start,end,4):
        p=off(va)
        if 0<=p<=len(payload)-4:
            w=struct.unpack_from("<I",payload,p)[0]
            literal.append(f"0x{va:08X}: 0x{w:08X}")
(out/"LITERAL_WORDS.txt").write_text("\n".join(literal)+"\n")

# Candidate call sites to routines observed in the Stage 11 control flow.
targets={0x4802E7EC:"menu_renderer",0x4802E844:"menu_helper_2e844",
         0x4802E920:"menu_helper_2e920",0x4802E9B4:"menu_helper_2e9b4",
         0x480052EC:"key_dispatch_candidate",0x480050E4:"delay_or_timer_candidate"}
branches=[]
for pos in range(0,len(payload)-4,2):
    va=base+prefix+pos
    for ins in thumb.disasm(payload[pos:pos+4],va,count=1):
        if ins.mnemonic=="bl":
            try: dest=int(ins.op_str.split("#")[-1],16)
            except Exception: continue
            if dest in targets: branches.append((va,dest))
lines=["Candidate Thumb BL sites (must be checked against coherent function context):"]
for site,dest in branches:
    lines.append(f"0x{site:08X} -> 0x{dest:08X} {targets[dest]}")
    lines += ["  "+x for x in dis(site-0x0C,0x24,thumb)]
(out/"CALL_SITES.txt").write_text("\n".join(lines)+"\n")

# Raw bytes around the key-event structure offsets accessed by the loops.
(out/"KEY_CONTEXT_BYTES.txt").write_text("\n".join(
    ["Global structure references observed in Stage 11: [r4,#0x138] and [r4,#0x13c].",
     "These are key-code candidates only; Stage 12 must establish the callee semantics.",
     *hexdump(0x4802EB70,0x70),
     *hexdump(0x4802ECC0,0x70)])+"\n")

summary=[
"Stage 12 focused menu/key-dispatch trace; read-only.",
f"image={img}",f"size={len(raw)}",f"sha256={sha}",f"expected_sha_match={sha==expected}",
f"mapping=VA 0x{base:08X} + payload offset 0x{prefix:X}",
"Stage 11 found coherent menu-renderer calls from the 0x4802EB60 and 0x4802EC84 regions.",
"Stage 12 expands those loops and inspects 0x48005200 onward, including candidate key dispatcher 0x480052EC.",
"Do not treat key-code fields or call-site scans as proof without confirming the callee and surrounding control flow.",
"No image bytes modified."
]
(out/"SUMMARY.txt").write_text("\n".join(summary)+"\n")
print((out/"SUMMARY.txt").read_text())
