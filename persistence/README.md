# On-device boot re-root

`GhostLock Boot` is the no-wipe persistence mechanism for the exact Shield
Experience 9.2.4 `mdarcy` build supported by this repository. It is an ordinary
userdata APK that receives Android's `BOOT_COMPLETED` broadcast. A foreground
service keeps its unprivileged UID alive while the hash-pinned GhostLock payload
runs, then removes its temporary notification and stops itself.

The APK does not make a verified partition writable and does not install `su`.
On every boot, Android initially creates stock UID-2000 `adbd`; the app then
exploits the kernel once and changes that live daemon to UID 0. Consequently,
there is a short non-root ADB window during startup. A truly static root `adbd`
would require a modified boot image or other verified-boot bypass, which is not
part of this no-wipe installation.

## Safety properties

- Exact fingerprint, kernel release, and embedded payload SHA-256 are checked
  before the trigger.
- A nonblocking file lock prevents concurrent runners.
- Persistent state permits at most one recorded trigger per Android boot count.
- The attempt is recorded before entering the kernel race, preventing a crash
  and reboot from forming an exploit loop.
- A global 15-minute cooldown carries across reboots and app-process restarts.
- A UID-0 runner refuses to invoke the exploit.
- The broadcast receiver is not exported. The tiny exported activity exists
  only to clear Android's newly-installed/stopped package state.
- The foreground service and waiter prevent Android's empty-process reaper from
  killing the native race, and stop as soon as the native runner exits.
- Immediately before `exec`, the runner clears ART's inherited signal mask so
  the payload's targeted SIGUSR1 futex-wait release behaves as it does from an
  ordinary ADB shell.

The package is deliberately marked debuggable so the installer and owner can
seed and inspect its private watchdog state with `run-as`. This does not grant
another app access to the package sandbox.

## Release artifacts

```text
persistence/app/build/ghostlock-boot-mdarcy-9.2.4.apk
persistence/app/build/libghostlock_runner.so
exploit/build/preload-mdarcy-9.2.4.so
```

The APK contains the other two artifacts under `lib/arm64-v8a/`. Release hashes
are listed in [`../SHA256SUMS`](../SHA256SUMS). The release APK uses a signing
key kept outside this repository.

## Install

Download the release APK into `persistence/app/build/`, then run from an
authorized Windows ADB host:

```powershell
./persistence/install.ps1 `
  -Target SHIELD_ADDRESS:5555 `
  -AdbPath C:/path/to/platform-tools/adb.exe
```

The installer verifies the APK and target, installs the app, transactionally
disables the runner while seeding its state, clears Android's stopped-package
flag, and arms the receiver for the next boot. It does not reboot the Shield.
By default, installation records the current time as the most recent attempt;
wait 15 minutes before a deliberate test reboot so the native process does not
need to remain alive waiting out the initial cooldown. The optional
`-LastAttemptEpoch` parameter is intended for recovery tooling that already
knows the timestamp of the last real exploit attempt.

To inspect state and logs:

```powershell
adb -s SHIELD_ADDRESS:5555 shell run-as com.cyberbalsa.ghostlockboot `
  cat files/watchdog.state
adb -s SHIELD_ADDRESS:5555 shell run-as com.cyberbalsa.ghostlockboot `
  cat files/boot.log
```

A boot attempt begins with `starting GhostLock boot attempt`; subsequent
payload diagnostics are appended to the same file because the runner redirects
stdout and stderr before `exec`. Success is confirmed by `configfs adbd root
installed` plus UID 0 from a fresh ADB transport. The payload process itself
correctly remains at the app UID, so its final `root=NO` field does not describe
the separately patched `adbd` task.

## Build

Build the payload and native runner with the NDK image:

```sh
podman build -t ghostlock-android:ndk-r29 -f build/Containerfile .
podman run --rm -v "$PWD:/src:Z" -w /src/exploit \
  ghostlock-android:ndk-r29 make -B
podman run --rm -v "$PWD:/src:Z" -w /src/persistence/app \
  ghostlock-android:ndk-r29 make -B
```

Build the packaging-tools image and sign the APK with a PKCS#12 keystore:

```sh
podman build -t ghostlock-apk-tools:bookworm \
  -f persistence/app/Containerfile.tools .
podman run --rm \
  -v "$PWD:/src:Z" \
  -v /path/to/signing-directory:/sign:Z \
  -e GHOSTLOCK_KEYSTORE=/sign/ghostlock-release.p12 \
  -e GHOSTLOCK_KEY_PASSWORD_FILE=/sign/apksigner-passwords \
  -w /src/persistence/app \
  ghostlock-apk-tools:bookworm sh build-apk.sh
```

The password file is consumed separately for the keystore and key password, so
it must contain the password twice, one line per prompt. Never commit the
keystore or password file.

## Remove

```powershell
./persistence/uninstall.ps1 `
  -Target SHIELD_ADDRESS:5555 `
  -AdbPath C:/path/to/platform-tools/adb.exe
```

Uninstalling removes the package and all private state. It does not undo root
credentials already applied to the currently running `adbd`; those disappear
on the next `adbd` restart or device reboot.
