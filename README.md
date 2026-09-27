# fleur_mt6781_bpf-patch-4.19-kernel
A repository where 4.19.325-cip129-st13-g4284dce0f576-dirty MT6781 kernel gets patched, dumped from POCO M4 Pro 4G 8/256 variant via BROM-Kamakiri MTK V6 exploit with the use of [`mtkclient`](https://github.com/bkerler/mtkclient).

The `dump` folder houses the `magiskboot` unpacked boot_a-current.img which contains the faulty kernel.

## The Cause
MediaTek introduced a proprietary commit into their `4.14` and `4.19` kernels to suppress `ubsan` errors. This commit accidentally broke `arraymap`, causing the Android network daemon (netd) to fail to register network maps. Wi-Fi and mobile data will show as connected, but the system cannot route traffic, resulting in zero internet access.
