#!/usr/bin/env python3
"""
MTK BPF arraymap kernel patcher (UNIVAN_T790 / mt6873, 4.19.191-perf+).

Background
----------
MediaTek's downstream commit "[ALPS05247589] bpf: fix ubsan error"
(https://gist.github.com/R0rt1z2/8af7735c6c3802148fa4da61b3cba506) added a
bounds check to the bpf array-map lookup paths in kernel/bpf/arraymap.c:

    if (unlikely(sizeof(array->value) <
        array->elem_size * (index & array->index_mask)))
            return -EINVAL;

Because `sizeof(array->value)` is only 28 bytes (the inline placeholder of the
flexible-array member), every lookup whose computed slot offset reaches or
exceeds that constant is wrongly rejected with -EINVAL. This indirectly broke
BPF array maps and caused connectivity issues on Android 12 based ROMs.

The fix is to revert the MTK check so the original code path runs
unconditionally. In the compiled AArch64 Image for this device, each of the
four affected arraymap functions contains the same two-instruction guard
(register numbers vary between sites):

    ldrb   w?, [x?, #0x12e]      ; load the flag byte @ struct offset 0x12e
    tbnz   w?, #2, +8            ; if bit 2 is set, SKIP the next instruction
    <skipped instruction>        ; adr/nop pair setting up the normal path
    <branch target>              ; out-of-line path (kfunc registration /
                                 ; -EINVAL style early-out blocks)

NOPing both instructions makes the guard inert: the skipped instruction now
always executes and the fall-through target is untouched, so the patch is
length-preserving (no relocations, identical image size) and semantically
equivalent to reverting the MTK hunk in every lookup/update entry point.

Matching is done purely on AArch64 encodings (scaled LDRB imm12 == 0x12e
immediately followed by TBNZ #2 with imm14 == +8 on the same Rt). This exact
combination occurs precisely 4 times in the whole 39 MB Image - the four
arraymap sites at file offsets 0x37a45c, 0x37b2ec, 0x37d650 and 0x37f098 -
and nowhere else, which makes the signature safe without needing per-kernel
offset tables.

The tool never rewrites anything else, validates alignment/instruction
decoding when capstone is available, and prints a per-site report.

Usage:
    python3 tools/patch_kernel.py <input Image> <output Image> [--force]
"""

import argparse
import struct
import sys

# ---------------------------------------------------------------------------
# AArch64 encodings
# ---------------------------------------------------------------------------
NOP_U32 = 0xD503201F
NOP_BYTES = struct.pack("<I", NOP_U32)

# ldrb w?, [x?, #imm12]  (unsigned offset, scaled by 1):  0x39400000 / mask 0xFFC00000
LDRB_MASK = 0xFFC00000
LDRB_BASE = 0x39400000
OFF_CPU_SHIFTED = 0x12E >> 0  # byte offset used directly as imm12 for LDRB

# tbnz w/x?, #2, #+8  (exact encoding observed on this kernel: 0x37100148 for Rt=w8)
#   [31] x | [30] 0 | [29] op=1 | [28:25]=1101 | [24] b5[0] | [23:19] b5[5:1]
#   | [18:5] imm14 | [4:0] Rt
# For bit #2 (b5=2): bit24=0, bits[23:19]=00010.
# imm14 = +2 instructions (+8 bytes) -> imm field value 2 at bits[18:5].
# Mask ignores the x-size bit [31] and Rt [4:0]; same-Rt pairing is checked separately.
TBNZ2_P8_WORD = 0x37100148
TBNZ2_P8_MASK = 0x7F1FFFFF     # keep bits [30:5], ignore x bit and Rt
TBNZ2_P8_BASE = TBNZ2_P8_WORD & TBNZ2_P8_MASK


def decode_ldrb_off_0x12e(word):
    """Return Rt if `word` is 'ldrb w<Rt>, [x<n>, #0x12e]' else None."""
    if (word & LDRB_MASK) != LDRB_BASE:
        return None
    imm12 = (word >> 10) & 0xFFF
    if imm12 != 0x12E:
        return None
    return word & 0x1F


def decode_tbnz_bit2_plus8(word):
    """Return Rt if `word` is 'tbnz w<x>, #2, +8' else None."""
    if (word & TBNZ2_P8_MASK) != TBNZ2_P8_BASE:
        return None
    return word & 0x1F


def find_sites(data):
    """Yield file offsets of every MTK arraymap check site in `data`."""
    n = len(data) - (len(data) % 4)
    for off in range(0, n - 8, 4):
        rt_a = decode_ldrb_off_0x12e(struct.unpack_from("<I", data, off)[0])
        if rt_a is None:
            continue
        rt_b = decode_tbnz_bit2_plus8(struct.unpack_from("<I", data, off + 4)[0])
        if rt_b is None:
            continue
        if rt_a == rt_b:
            yield off


def verify_with_capstone(data, sites):
    """Optional disassembly verification (no-op if capstone isn't installed)."""
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    except ImportError:
        print("[*] capstone not installed - skipping disasm verification")
        return True
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    ok = True
    for s in sites:
        seq = list(md.disasm(data[s:s + 16], s))
        names = [(i.mnemonic, i.op_str.strip()) for i in seq]
        if len(seq) != 4 or names[0][0] != "ldrb" or names[1][0] != "tbnz":
            print(f"[!] unexpected decoding at 0x{s:x}: {names}")
            ok = False
        else:
            print(f"    0x{s:x}: {names[0][0]} {names[0][1]} ; {names[1][0]} {names[1][1]}"
                  f"  (skips: {names[2][0]} {names[2][1]})")
    return ok


def main():
    ap = argparse.ArgumentParser(description="MTK BPF arraymap kernel patcher")
    ap.add_argument("input", help="unpacked kernel Image (input)")
    ap.add_argument("output", help="patched kernel Image (output)")
    ap.add_argument("--force", action="store_true",
                    help="apply even if the expected site count (4) is not matched")
    args = ap.parse_args()

    with open(args.input, "rb") as f:
        data = bytearray(f.read())

    orig_len = len(data)
    print(f"[*] Input:  {args.input} ({orig_len} bytes)")

    sites = list(find_sites(data))
    print(f"[*] Found {len(sites)} MTK arraymap bounds-check site(s): "
          + ", ".join(hex(s) for s in sites))

    if not sites:
        print("[!] No patchable sites found. Already patched, or unsupported kernel.")
        sys.exit(2)
    if len(sites) != 4 and not args.force:
        print("[!] Expected exactly 4 sites on this kernel - refusing (use --force).")
        sys.exit(3)

    print("[*] Site context (disassembly):")
    if not verify_with_capstone(data, sites) and not args.force:
        print("[!] Verification failed - refusing (use --force).")
        sys.exit(4)

    for s in sites:
        # sanity: don't double-patch an already-NOP'd pair
        if struct.unpack_from("<I", data, s + 4)[0] == NOP_U32:
            print(f"[-] Site 0x{s:x} already patched, skipping")
            continue
        data[s:s + 4] = NOP_BYTES          # ldrb w?,[x?,#0x12e] -> nop
        data[s + 4:s + 8] = NOP_BYTES      # tbnz w?,#2,+8       -> nop
        print(f"[+] Patched site at file offset 0x{s:x} (2 instructions NOPed)")

    assert len(data) == orig_len, "image size changed!"

    with open(args.output, "wb") as f:
        f.write(data)
    print(f"[+] Wrote patched kernel -> {args.output} ({len(data)} bytes, size preserved)")


if __name__ == "__main__":
    main()
