#!/usr/bin/env python3
"""
verify_kernel_patch.py — independent, fail-closed verification of the
kernel-level binary diff between the magiskboot-extracted original kernel and
the patched kernel, BEFORE any repack happens.

Checks (all mandatory; any failure => non-zero exit):
  * identical file sizes
  * input SHA-256 == --expect-original-sha256 (if given)
  * output SHA-256 == --expect-patched-sha256 (if given)
  * exactly --expect-changed-bytes differing bytes (default 8 = two 4-byte
    AArch64 instructions for this project's verified MT6781 patch)
  * the diff occurs at EXACTLY the expected (offset, original 4 bytes,
    replacement 4 bytes) windows - defaulting to the verified fleur sites:
        0x178628: e8f70736 -> d503201f   (tbz w8,#0,#0x178524 -> nop)
        0x1786cc: c8f20736 -> d503201f   (tbz w8,#0,#0x178524 -> nop)
  * no other byte anywhere differs

Writes a machine-readable JSON report (--report). Exit codes:
  0 ok | 2 size mismatch | 3 sha mismatch | 4 unexpected diff structure
"""
import argparse
import hashlib
import json
import sys

DEFAULT_EXPECTED = [
    {"offset": "0x178628", "original_bytes": "e8f70736", "replacement_bytes": "d503201f"},
    {"offset": "0x1786cc", "original_bytes": "c8f20736", "replacement_bytes": "d503201f"},
]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("original")
    ap.add_argument("patched")
    ap.add_argument("--report")
    ap.add_argument("--expect-original-sha256")
    ap.add_argument("--expect-patched-sha256")
    ap.add_argument("--expect-changed-bytes", type=int, default=8)
    ap.add_argument("--expected-windows-json",
                    help="JSON list of {offset,original_bytes,replacement_bytes}; "
                         "defaults to the verified fleur MT6781 windows")
    args = ap.parse_args()

    a = open(args.original, "rb").read()
    b = open(args.patched, "rb").read()
    sha_a = hashlib.sha256(a).hexdigest()
    sha_b = hashlib.sha256(b).hexdigest()
    print(f"[*] original: {args.original} ({len(a)} bytes) sha256={sha_a}")
    print(f"[*] patched : {args.patched} ({len(b)} bytes) sha256={sha_b}")

    def fail(code, msg):
        print(f"[!] VERIFY FAIL: {msg}", file=sys.stderr)
        sys.exit(code)

    if len(a) != len(b):
        fail(2, f"size mismatch: {len(a)} vs {len(b)}")
    if args.expect_original_sha256 and sha_a != args.expect_original_sha256.lower():
        fail(3, f"original sha256 mismatch (expected {args.expect_original_sha256})")
    if args.expect_patched_sha256 and sha_b != args.expect_patched_sha256.lower():
        fail(3, f"patched sha256 mismatch (expected {args.expect_patched_sha256})")

    windows = (json.loads(open(args.expected_windows_json).read())
               if args.expected_windows_json else DEFAULT_EXPECTED)

    diff_offs = [i for i in range(len(a)) if a[i] != b[i]]
    expected_offs = sorted(o + k for w in windows
                           for o in [int(w["offset"], 16)] for k in range(4))
    if len(diff_offs) != args.expect_changed_bytes:
        fail(4, f"{len(diff_offs)} differing bytes, expected {args.expect_changed_bytes}")
    if diff_offs != expected_offs:
        fail(4, f"diff offsets {[hex(x) for x in diff_offs[:16]]}... do not match expected "
                f"{[w['offset'] for w in windows]}")
    for w in windows:
        off = int(w["offset"], 16)
        orig = a[off:off + 4].hex()
        repl = b[off:off + 4].hex()
        if orig != w["original_bytes"]:
            fail(4, f"at {w['offset']}: original bytes {orig} != expected {w['original_bytes']}")
        if repl != w["replacement_bytes"]:
            fail(4, f"at {w['offset']}: replacement bytes {repl} != expected {w['replacement_bytes']}")
        print(f"[+] window {w['offset']}: {orig} -> {repl}  OK")

    print(f"[+] Kernel binary diff verified: exactly {len(diff_offs)} changed bytes, "
          f"no unexpected modifications.")

    if args.report:
        with open(args.report, "w") as f:
            json.dump({
                "schema": "fleur-kernel-diff-verification/v1",
                "original_file": args.original,
                "original_size": len(a),
                "original_sha256": sha_a,
                "patched_file": args.patched,
                "patched_size": len(b),
                "patched_sha256": sha_b,
                "changed_bytes_total": len(diff_offs),
                "windows": windows,
                "result": "PASS",
            }, f, indent=2)
        print(f"[+] Wrote verification report -> {args.report}")


if __name__ == "__main__":
    main()
