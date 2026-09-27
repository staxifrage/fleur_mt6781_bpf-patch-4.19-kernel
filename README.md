# fleur_mt6781_bpf-patch-4.19-kernel
A repository where 4.19.325-cip129-st13-g4284dce0f576-dirty MT6781 kernel gets patched, dumped from POCO M4 Pro 4G 8/256 variant via BROM-Kamakiri MTK V6 exploit with the use of [`mtkclient`](https://github.com/bkerler/mtkclient).

The `dump` folder houses the `magiskboot` unpacked boot_a-current.img which contains the faulty kernel.
The SHA-256 of the dumped kernel image (`dump/kernel`) is recorded in `output/checksums.json`. As of this
update it is:

```text
3c70a8671703f43a62ec4e0799df4ccb8acba78f762af51db99dcda4920b1388  dump/kernel
```

## The Cause
MediaTek introduced a proprietary commit into their `4.14` and `4.19` kernels to suppress `ubsan` errors. This commit accidentally broke `arraymap`, causing the Android network daemon (netd) to fail to register network maps. Wi-Fi and mobile data will show as connected, but the system cannot route traffic, resulting in zero internet access.

## AI evaluation and solution solving

### Update — 2026-09-27: patch-target search status (NOT FOUND — no blind patching)

We ran an automated, disassembly-based search for the exact BPF `BPF_MAP_LOOKUP_ELEM` size-check site
(`tools/patch_kernel.py` target pattern) inside the dumped kernel. Status of this iteration:

* **Upstream byte signature: 0 matches.** The 16-byte upstream fingerprint
  `48 01 00 35 82 22 40 b9 80 42 04 91 e1 03 13 aa` (from `kernel/bpf/syscall.c`, v4.19.y) does not
  occur anywhere in `dump/kernel`. Even its distinctive tail (`82 22 40 b9 80 42 04 91 e1 03 13 aa`,
  i.e. `ldr w?, [x18, #0x20]` + `mov x?, #0x1c`) has **zero** occurrences, so the literal upstream
  instruction sequence was transformed by the vendor toolchain.
* **Structural scans: no unique candidate.** Several structural searches over the whole ~32 MB image
  (capstone AArch64 disassembly, 4-byte aligned) were run with progressively relaxed filters, e.g.:
  - `cbz/cbnz` skipping exactly one instruction fed by an adjacent load — hundreds of generic hits,
    none in a BPF-like context;
  - windows containing `and`+`mul`/`madd` (mask-by-value_size then multiply) plus a conditional
    overflow branch (`b.hs/b.lo/...`) — 33 candidates, all unrelated subsystems;
  - tightening with `mov w?, #-1` / small-constant value-size loads / `ret` epilogue shapes — the
    surviving candidates are clearly not the check (e.g. `0x2e389c`, a CPU-capacity/`cap_done`-style
    loop, and `0x5e9a30`, a `total_map_members`-style bounds computation). None shows the
    `value_size * elem_size >= 1MiB -> -EINVAL(0x16)` shape feeding the null-return skip.
* **Why:** MTK's ubsan-suppression commit rewrites these comparisons — notably replacing the
  compiler's `cmp #imm` + `b.cc` pairs with `subs`/flag-reuse sequences and constant blurring — so
  the upstream byte pattern is destroyed and pure static matching against this dump is unreliable.
* **Decision:** per the project's safety rules we are **not** applying any offset-based patch in this
  state. `output/patch_report.json` remains at its previous verified state and `dump/kernel` is
  untouched (checksum above is the reference point for any future attempt).
* **Next steps planned:**
  1. Locate the BPF syscall table / `map_get_elem_value` callers statically (e.g. via the `bpf`
     syscall wrapper and `sys_bpf` string/xrefs) to narrow the search window to `kernel/bpf/*` text
     range before pattern matching.
  2. Re-run the scan against a *decompressed/relocated* view if additional boot images become
     available, and cross-check candidate sites by requiring the `-EINVAL` (`mov w0, #-0x16`) path
     to dominate the null-store path.
  3. If a single unambiguous site survives, record it here with its file offset and surrounding
     disassembly before patching, so the change stays auditable.

### Previous entries

* **Initial plan (archived):** apply the upstream 4.19.y one-instruction fix — turn the always-taken
  `b` that skips the null-store in the size check into `b.ne` — using
  `python tools/patch_kernel.py dump/kernel --offset <off> --pattern <hex> --replace-hex <hex>`
  after the site is uniquely identified. Identification is still pending (see update above).
