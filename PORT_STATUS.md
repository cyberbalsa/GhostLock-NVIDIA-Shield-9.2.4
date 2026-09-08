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

This is a live, volatile root. Rebooting recreates `adbd` with its stock
credentials and restores the SELinux globals, so rerun the exploit after a
reboot if root is needed again. The payload refuses to re-enter GhostLock when
the calling ADB shell is already UID 0 unless
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

## Long-term ADB root

The live credential patch survives client disconnects but not an `adbd`
restart or reboot. The target reports locked, green Verified Boot and enforcing
dm-verity, so installing an on-device boot hook without an independently
validated boot-chain bypass would make the device fail verification.

`watchdog/` instead supplies a rootless Podman/systemd user service for an
always-on authorized ADB host. It checks the exact fingerprint, kernel release,
payload hash, current boot ID, and fresh-shell UID before acting. Persistent
state enforces a 15-minute retry cooldown and a two-attempt-per-boot ceiling.
This provides automatic re-root after a normal reboot without modifying boot,
system, vendor, userdata contents other than the staged payload, or the
bootloader state.

The deployed service was verified end to end: after a normal reboot it saw a
fresh UID 2000 `adbd`, made one attempt, and a new ADB transport reported UID 0
with the expected capability mask and seccomp state.

## Runtime caveats

- The race can panic the kernel. The Shield reboots normally and userdata has
  remained intact, but this is not a persistence mechanism.
- The intentional short `copy_from_user` fault clears `selinux_enforcing` and
  its adjacent `default_noexec` integer. Both return to stock values on reboot;
  `default_noexec` has no effect while SELinux is permissive.
- Do not force the GhostLock trigger from an already-root shell. A diagnostic
  attempt showed that the privileged `sched_setattr` path changes PI behavior
  and can panic at `_raw_spin_trylock`. The default UID-0 guard prevents this.
