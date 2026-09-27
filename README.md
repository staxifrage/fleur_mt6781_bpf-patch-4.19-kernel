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

### Update — 2026-09-27 (later): TARGET FOUND — `array_map_update_elem()` located at `dump/kernel` offset `0x178080`

The previous "NOT FOUND" status below was produced while searching the wrong semantic site. The
correct target, per MediaTek commit `ALPS05247589` ("bpf: fix ubsan error", James Hsu,
MTK-Commit-Id `77ac33722f4c2fbab1ec71281a1ddccb80e2b5e7`), is **not** the `BPF_MAP_LOOKUP_ELEM`
size check in `kernel/bpf/syscall.c` — it is the vendor-added bounds check inside
`kernel/bpf/arraymap.c::array_map_update_elem()`:

```c
else {
        if (unlikely(sizeof(array->value) <
            array->elem_size * (index & array->index_mask)))
                return -EINVAL;
        memcpy(array->value + array->elem_size * (index & array->index_mask),
               value, map->value_size);
}
```

#### Identification of the function (`0x178080`)

`array_map_update_elem()` was positively identified by its full control/data flow, not by generic
byte patterns:

* prologue at `0x178080`, stack canary loaded from `__stack_chk_guard` (`0x18d6d18`);
* shared `-EINVAL` error epilogue at `0x1780d8`: `mov w22, #-0x16` → common return path
  (`mov w0, w22` / canary check / `ret` at `0x1780f0–0x178110`) — note the compiler materializes
  `-EINVAL` **once**, in a register-preserved epilogue, which is why requiring an adjacent
  `mov w0, #-0x16` is the wrong filter;
* flags validation via `ldr x23,[x1,#0x28]` + `tst x23,#-5` → `b.ne` to the `-EINVAL` epilogue
  (`0x1780b0–0x1780b4`); `BPF_NOEXIST` test via `ldr w9,[x0,#0x2c]` + `tbnz w9,#0x1f` (`0x1780cc`);
* percpu vs normal-array dispatch via `tbz/tbnz #0x1f` on the map-type word at `[map,#0x2c]`;
* the normal-array store is `bl #0xcb40` (kernel `memcpy`) with size taken from
  `ldr w8,[x19,#0x20]` = `map->value_size` (e.g. `0x1786a8–0x1786b8` and `0x178708–0x178718`);
* the percpu element-copy loop also ends in `bl #0xcb40` (`0x178540–0x178554`), followed by the
  MTK-check flag reload.

#### The MediaTek check as compiled here

Clang lowered the bogus comparison into a predicate stored on the stack at `[x29,#-0x34]`, tested
by **two conditional branches** that both jump to the error-cleanup epilogue at `0x178524` (which
restores state and returns `w22`, i.e. `-EINVAL`):

```text
0x178624: a8 c3 5c b8   ldur w8, [x29, #-0x34]     ; reload MTK-check result flag
0x178628: e8 f7 07 36   tbz  w8, #0, #0x178524     ; <-- MTK branch #1 -> -EINVAL

0x1786c8: a8 c3 5c b8   ldur w8, [x29, #-0x34]
0x1786cc: c8 f2 07 36   tbz  w8, #0, #0x178524     ; <-- MTK branch #2 -> -EINVAL
```

Branch #1 sits immediately after the percpu `memcpy` tail; branch #2 sits immediately after the
normal-array `memcpy(array->value + elem_size*(index & index_mask), value, map->value_size)` at
`0x1786b8`. Falling through either branch continues into the normal success path
(`0x17862c` / `0x1786d0 → 0x17862c`), so neutralizing only these two branches preserves all
legitimate update semantics — exactly the intended `mtk-bpf-patcher` transformation (reference
build used `cbnz w8` → `nop`; this build uses `tbz` because the predicate lives in a stack slot).

#### Patch (validated signatures, unique across the whole image)

Replace each 4-byte branch word with `d5 03 20 1f` (`nop`). Uniqueness verified over all of
`dump/kernel` using the full 8-byte sequences including the preceding flag reload:

| file offset | BEFORE (pattern)             | instruction              | AFTER (replace)          |
|-------------|------------------------------|--------------------------|--------------------------|
| `0x178624`  | `a8c35cb8 e8f70736`          | `ldur w8,[x29,#-0x34]` + `tbz w8,#0,#0x178524` | `a8c35cb8 d503201f` |
| `0x1786c8`  | `a8c35cb8 c8f20736`          | `ldur w8,[x29,#-0x34]` + `tbz w8,#0,#0x178524` | `a8c35cb8 d503201f` |

Each combined pattern has exactly **one** match in the image (checked programmatically). No patch
has been applied to `dump/kernel` yet (current reference checksum:
`8e69dd6c28aa0b8ea9143bc3b01d6e234cc01016963c4dd7889199088450db1f`; note this differs from the
older `3c70a867…` value quoted above — the dump was re-unpacked since that entry was written, and
the offsets/signatures in this section were verified against the current file); recommended application via
`python tools/patch_kernel.py dump/kernel --offset 0x178628 --pattern a8c35cb8e8f70736 --replace-hex a8c35cb8d503201f`
(and likewise for `0x1786cc`), followed by runtime confirmation that `update_elem` on a small-index
array map returns success post-patch where it previously failed, breaking netd's map registration.

### Update — 2026-09-27: patch-target search status (NOT FOUND — no blind patching) *(superseded by the entry above)*

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
