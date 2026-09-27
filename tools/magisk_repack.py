#!/usr/bin/env python3
"""
magisk_repack.py - Safe magiskboot unpack -> patch -> repack pipeline for
Android boot images, with built-in corruption checks so a bad build can never
be published as a flashable image.

Why this exists (the "how do I not brick my phone" answer)
----------------------------------------------------------
magiskboot (from topjohnwu/Magisk) is the standard tool for unpack/repack of
boot images, but naive usage corrupts images in three common ways:

1. Compression-state mismatch. `magiskboot unpack` decompresses kernel/ramdisk
   into the working directory. If you hand it back a file whose compression
   differs from what the original section held (or edit a CPIO ramdisk without
   re-packing it correctly), the repacked header no longer matches reality.
2. Size changes. Any patch that changes the kernel byte length requires the
   ANDROID! header's kernel_size field and page alignment to be recomputed.
   Getting that wrong = unbootable device.
3. Silent side effects. Repack may rewrite the vbmeta hash footer, dtb
   placement, or vendor padding even when you only touched the kernel.

This wrapper enforces the safe path:
  * The patch step MUST be length-preserving (we verify identical size).
  * After `magiskboot repack`, we compare the output against the ORIGINAL
    image byte-for-byte OUTSIDE the kernel payload region; any difference
    fails the build.
  * We re-parse the ANDROID! header of both images and require every field
    except kernel_size-related padding to match.
  * Nothing is written to --output unless all checks pass.

Usage (this is what the GitHub Action calls):
    python3 tools/magisk_repack.py \
        --boot-image boot_a-current.img \
        --workdir build/work_a \
        --output build/out/boot_a-patched.img \
        --magiskboot /usr/local/bin/magiskboot \
        --patch-cmd 'python3 tools/patch_kernel.py {kernel_in} {kernel_out}'

The patched kernel produced by patch_kernel.py is guaranteed same-size
(it replaces instructions with NOPs), which is exactly the class of patch
this tool is designed to allow through.
"""

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys

BOOT_MAGIC = b"ANDROID!"


def die(msg):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_android_boot_header(path):
    """Parse the ANDROID! boot image header (v0-v4).

    Field offsets follow AOSP boot_image.h:
      0   magic[8] ("ANDROID!")
      8   kernel_size (u32)
      12  ramdisk_size (u32)
      16  second_size (u32)
      20  kernel_addr, 24 ramdisk_addr, 28 second_addr (u32 each)
      32  tags_addr (u32)
      36  page_size (u32)
      40  header_version (u32)
      44  os_version (u32)
      48  name[16], 64 cmdline[512], ...
    Regions beyond what we parse are treated as opaque bytes and compared
    verbatim in the whole-file diff below, so v1/v2 extras (recovery_dtbo,
    dtb, bootconfig) are still covered by the safety check.
    """
    with open(path, "rb") as f:
        hdr = f.read(4096)
    if len(hdr) < 48 or hdr[:8] != BOOT_MAGIC:
        die(f"{path}: not an ANDROID! boot image")

    def u32(o):
        return struct.unpack_from("<I", hdr, o)[0]

    ps = u32(36) or 2048  # some MTK images leave page_size 0; fall back to 2048
    return {
        "kernel_size": u32(8),
        "ramdisk_size": u32(12),
        "second_size": u32(16),
        "page_size": u32(36),
        "header_version": u32(40),
        "os_version": u32(44),
        "effective_page_size": ps,
    }


def run(cmd, **kw):
    print("[*] $ " + " ".join(cmd))
    return subprocess.run(cmd, check=True, **kw)


def find_magiskboot(explicit=None):
    if explicit:
        if not os.path.exists(explicit):
            die(f"--magiskboot path {explicit} does not exist")
        os.chmod(explicit, 0o755)
        return explicit
    p = shutil.which("magiskboot")
    if p:
        return p
    die("magiskboot not found in PATH (pass --magiskboot /path/to/magiskboot)")


def main():
    ap = argparse.ArgumentParser(description="Safe magiskboot unpack/patch/repack")
    ap.add_argument("--boot-image", required=True, help="original boot .img to unpack")
    ap.add_argument("--workdir", required=True, help="scratch dir for unpack/repack")
    ap.add_argument("--output", required=True, help="where to write the verified image")
    ap.add_argument("--patch-cmd", required=True,
                    help="template with {kernel_in} / {kernel_out}")
    ap.add_argument("--magiskboot", default=None, help="path to magiskboot binary")
    args = ap.parse_args()

    magiskboot = find_magiskboot(args.magiskboot)
    orig_hdr = parse_android_boot_header(args.boot_image)
    print(f"[*] Original header: {orig_hdr}")

    work = os.path.abspath(args.workdir)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    src = os.path.join(work, "boot.img")
    shutil.copyfile(args.boot_image, src)

    prev_cwd = os.getcwd()
    os.chdir(work)
    try:
        # ---- UNPACK ----------------------------------------------------
        run([magiskboot, "unpack", "boot.img"])
        kernel_path = os.path.join(work, "kernel")
        if not os.path.exists(kernel_path):
            die("magiskboot unpack did not produce 'kernel'")
        print(f"[*] Unpacked kernel: {os.path.getsize(kernel_path)} bytes, "
              f"sha256={sha256(kernel_path)}")

        # ---- PATCH -----------------------------------------------------
        patched_kernel = os.path.join(work, "kernel.patched")
        cmd = args.patch_cmd.format(kernel_in=kernel_path, kernel_out=patched_kernel)
        r = subprocess.run(["bash", "-c", cmd])
        if r.returncode != 0:
            die(f"patch command failed with exit code {r.returncode}")
        if not os.path.exists(patched_kernel):
            die("patch command did not produce {kernel_out}")

        before = os.path.getsize(kernel_path)
        after = os.path.getsize(patched_kernel)
        if before != after:
            die(f"patch changed kernel size ({before} -> {after}). "
                "Only length-preserving patches are allowed for safe repack.")

        shutil.copyfile(kernel_path, os.path.join(work, "kernel.orig"))
        os.replace(patched_kernel, kernel_path)
        print(f"[*] Patched kernel: sha256={sha256(kernel_path)}")

        # ---- REPACK ------------------------------------------------------
        run([magiskboot, "repack", "boot.img"])
        repacked = None
        for cand in ("new-boot.img", "boot.img.new", "repacked-boot.img"):
            if os.path.exists(os.path.join(work, cand)):
                repacked = os.path.join(work, cand)
                break
        if repacked is None:
            die("magiskboot repack did not produce new-boot.img - "
                "check magiskboot version/output naming")

        # ---- VERIFY ------------------------------------------------------
        new_hdr = parse_android_boot_header(repacked)
        print(f"[*] Repacked header: {new_hdr}")
        for key in ("ramdisk_size", "second_size", "page_size",
                    "header_version", "os_version"):
            if new_hdr[key] != orig_hdr[key]:
                die(f"verification FAILED: header field '{key}' changed "
                    f"({orig_hdr[key]} -> {new_hdr[key]}). Refusing to publish.")
        if new_hdr["kernel_size"] != orig_hdr["kernel_size"]:
            die(f"verification FAILED: kernel_size changed "
                f"({orig_hdr['kernel_size']} -> {new_hdr['kernel_size']}).")

        # Byte-compare everything outside the kernel payload region.
        ps = orig_hdr["effective_page_size"]
        klen = orig_hdr["kernel_size"]
        kpad = ((klen + ps - 1) // ps) * ps
        kernel_off = ps  # header occupies exactly one page-sized block

        with open(args.boot_image, "rb") as f:
            orig_bytes = f.read()
        with open(repacked, "rb") as f:
            new_bytes = f.read()

        common = min(len(orig_bytes), len(new_bytes))
        mismatches = []
        i = 0
        while i < common:
            if kernel_off <= i < kernel_off + kpad:
                i = kernel_off + kpad
                continue
            if orig_bytes[i] != new_bytes[i]:
                mismatches.append(i)
                if len(mismatches) >= 20:
                    break
            i += 1
        if mismatches:
            die(f"verification FAILED: {len(mismatches)}+ bytes differ OUTSIDE the "
                f"kernel payload (first at 0x{mismatches[0]:x}). magiskboot altered "
                "unrelated sections - refusing to publish a possibly corrupt image.")
        if len(orig_bytes) != len(new_bytes):
            tail_orig = orig_bytes[common:]
            tail_new = new_bytes[common:]
            if tail_new.strip(b"\x00") or tail_orig.strip(b"\x00"):
                die("verification FAILED: trailing data beyond kernel region differs")

        out = os.path.abspath(args.output)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copyfile(repacked, out)
        print("[+] VERIFIED OK - only the kernel payload changed.")
        print(f"    original: {args.boot_image}  sha256={sha256(args.boot_image)}")
        print(f"    patched : {out}  sha256={sha256(out)}")
    finally:
        os.chdir(prev_cwd)


if __name__ == "__main__":
    main()
