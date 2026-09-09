# NVIDIA Shield mdarcy 9.2.4 GhostLock port status

## Result

The live `adbd` process was rooted successfully on Shield Experience 9.2.4
without unlocking the bootloader, wiping userdata, installing `su`, or changing
the wallpaper. A fresh ADB connection reports:

```text
uid=0(root) gid=0(root) ... context=u:r:shell:s0
adbd Uid/Gid: 0/0/0/0
CapInh/CapPrm/CapEff/CapBnd/CapAmb: 0000003fffffffff
Seccomp: 0
SELinux: permissive
```

The credential change itself is live and volatile: rebooting recreates `adbd`
with stock credentials and restores the SELinux globals. The bundled userdata
APK now performs that re-exploitation autonomously after `BOOT_COMPLETED`, so
no external host is required after installation. The payload refuses to
re-enter GhostLock when the calling ADB shell is already UID 0 unless
`GHOSTLOCK_FORCE_ROOT_TRIGGER=1` is explicitly supplied.

## Device and OTA

- Fingerprint: `NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4387.0822:user/release-keys`
- Kernel: `4.9.141-tegra-gb6e5605a #2 SMP PREEMPT Fri Jan 30 20:55:30 PST 2026 aarch64`
- Android security patch: `2026-01-05`
- Link-time `_text`: `0xffffff8008080000`; runtime kernel offset is disabled.
- The official 9.2.4 full OTA was checksum-verified before installation and
  userdata remained intact.

## Proven exploit chain

1. The live 9.2.4 `remove_waiter()` machine code still clears
   `current->pi_blocked_on`, confirming the vulnerable pre-fix GhostLock path.
2. A deterministic `MCAST_BLOCK_SOURCE` stack stamp places the stale waiter at
   `+0xb0`.
3. The order-2 `mm_struct` slab page is reclaimed with a shaped skb payload.
4. A full, disjoint fake rt-mutex/task layout redirects `ashmem_misc.fops` to a
   fake table using the legacy 4.9 configfs read/write handlers.
5. The configfs primitive reads the global task list and locates `adbd`.
6. One bounded write changes only `cred+4..cred+79`: eight IDs, securebits, and
   five capability words. The `cred` prefix, security pointer, keyring pointers,
   user namespace, group info, and RCU fields are verified unchanged.
7. The original ashmem operations and boot-ID pointer are restored before the
   exploit process exits.

The pipe-buffer physical-RW stage inherited from the reference exploit is not
used for this target.

## Exact 9.2.4 layout corrections

NVIDIA inserted an eight-byte field before the credential pointers relative to
the published 9.2.2 source. Live reads established:

```text
task_struct.real_cred = 1808
task_struct.cred      = 1816
task_struct.comm      = 1824
task_struct.seccomp   = 1992
task_struct.pi_lock   = 2020
task_struct.pi_waiters= 2032
task_struct.pi_blocked_on = 2048
```

`cred_jar` uses 192-byte objects; `struct cred` is 168 bytes. The bounded
credential write is 76 bytes plus one verified zero guard byte, entirely within
the same slab object. The exact kernel's last capability is 37, giving the full
mask `0x3fffffffff`.

## Build and deployed artifact

- Target header: `exploit/targets/shield-mdarcy-9.2.4/target.h`
- Generator: `analysis/generate_mdarcy_target.py`
- Output: `exploit/build/preload-mdarcy-9.2.4.so`
- Size: `156912` bytes
- SHA-256: `a3a1e75b627d8dd419e9bafd2a73082a8647510bf6ce4f975e52baf5aa1d0761`
- Device path: `/data/local/tmp/preload-mdarcy-9.2.4.so`

The binary was built with Android NDK r29 in Podman. The release payload does
not embed or install `su`, a daemon, or a wallpaper artifact.

Autonomous boot artifacts:

- Native runner: `libghostlock_runner.so`, 19896 bytes,
  SHA-256 `56fb508527ffe7da5ab79f857c9d51edbb19b940dcfc88753146927e848a2cf6`.
- Signed APK: `ghostlock-boot-mdarcy-9.2.4.apk`, 78324 bytes,
  SHA-256 `5ced50985a40063f8d3a0d9497b5b850b7e085fac2c35b028956dcfaf99e9495`.
- APK package/version: `com.cyberbalsa.ghostlockboot`, version code 2,
  version name 1.1.0; verified with APK signature schemes v2 and v3.

## Fresh-boot invocation

Set `GHOSTLOCK_ADBD_PID` to the current result of `pidof adbd`:

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

Verify from a new connection with `adb shell id` and by inspecting
`/proc/$(pidof adbd)/status`.

## Autonomous on-device ADB root

`persistence/` contains a release-signed userdata APK. Its non-exported boot
receiver starts a temporary foreground service, which retains an unprivileged
native runner for the duration of the race. The runner validates the exact
fingerprint, kernel release, and embedded payload hash; holds a nonblocking
lock; records no more than one attempt for each Android boot count; and applies
a 15-minute cooldown across boots. State is written before the vulnerable
operation so a panic cannot form a reboot loop.

An Android app inherits ART's blocked-signal mask. During validation,
SIGUSR1 was observed both pending on the GhostLock waiter (`SigPnd=0x200`) and
blocked (`SigBlk` contained `0x200`). The final runner clears that mask before
`exec`, allowing the exploit's targeted futex-wait release to behave exactly as
it does from an ADB shell. A waiter thread keeps the foreground service alive
until the native process exits, then removes the notification and stops the
service.

The final build was verified end to end on 2026-09-08 with the external host
watchdog stopped:

- Before reboot: boot count 133, UID 2000, SELinux enforcing.
- After reboot: boot count 134, boot ID
  `1f2f114b-69c8-4d49-a3ab-dd697270708e`; the first fresh transport was still
  UID 2000 and enforcing.
- At epoch `1788915831`, the app ran as UID/GID 10069, seccomp mode 2, and
  `u:r:untrusted_app_27:s0:c69,c256,c512,c768`.
- At 21:03:58 EDT, the kernel task walk found PID 3532 with `comm=adbd` and
  installed UID/GID 0 plus capability mask `0x3fffffffff`; SELinux changed
  from enforcing to permissive.
- A new ADB transport reported UID/GID 0, all five capability sets equal to
  `0000003fffffffff`, and seccomp mode 0. The app service and active
  notification were gone.
- The Linux fallback unit remained inactive throughout and was subsequently
  masked.

This is autonomous per-boot re-exploitation, not a verified-firmware change.
There is a short stock-`adbd` window on every boot, and an unusual later
`adbd` restart loses root until the next reboot. Making `adbd` start statically
as root would require a modified boot image or another verified-boot bypass,
which is outside the locked, no-wipe design. `watchdog/` remains available as a
deliberately disabled recovery fallback.

## Runtime caveats

- The race can panic the kernel. The Shield reboots normally and userdata has
  remained intact; the boot app's pre-trigger state and cooldown reduce the
  risk of a repeated crash loop.
- The intentional short `copy_from_user` fault clears `selinux_enforcing` and
  its adjacent `default_noexec` integer. Both return to stock values on reboot;
  `default_noexec` has no effect while SELinux is permissive.
- Do not force the GhostLock trigger from an already-root shell. A diagnostic
  attempt showed that the privileged `sched_setattr` path changes PI behavior
  and can panic at `_raw_spin_trylock`. The default UID-0 guard prevents this.
