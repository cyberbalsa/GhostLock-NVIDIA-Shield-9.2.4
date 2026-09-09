# Host-side persistent ADB root

The exploit changes the credentials of the live `adbd` task. That survives
client disconnects, but Android recreates stock `adbd` credentials after an
`adbd` restart or device reboot.

This watchdog is the external-host fallback to the on-device mechanism in
`persistence/`. A rootless Podman service on an always-on Linux host waits for
the exact supported Shield fingerprint and kernel, checks whether a fresh ADB
shell is UID 0, and reapplies the hash-pinned payload only when needed.

Safety controls:

- exact `mdarcy` fingerprint and kernel allowlist;
- exact payload SHA-256 check before startup;
- no exploit run while `adbd` is already root;
- 15-minute retry cooldown and two attempts per boot by default;
- state retained across container restarts;
- no changes to boot, system, or vendor partitions.

## Install

Authorize the Linux host for network ADB first and make sure its
`~/.android/adbkey` is available. Build the payload as described in the main
README, then run:

```sh
./watchdog/install.sh SHIELD_ADDRESS:5555
systemctl --user status ghostlock-shield-watchdog.service
journalctl --user -u ghostlock-shield-watchdog.service -f
```

The systemd user manager must start at boot. Most always-on hosts can enable
that once with `loginctl enable-linger "$USER"` from an administrator account.

## Stop or remove

To retain the host fallback but prevent it from starting, mask the generated
unit:

```sh
systemctl --user mask --now ghostlock-shield-watchdog.service
```

Restore it later with:

```sh
systemctl --user unmask ghostlock-shield-watchdog.service
systemctl --user start ghostlock-shield-watchdog.service
```

To remove the Quadlet instead:

```sh
systemctl --user stop ghostlock-shield-watchdog.service
rm -f ~/.config/containers/systemd/ghostlock-shield-watchdog.container
systemctl --user daemon-reload
```

This is host-managed persistence, not a permanent firmware patch. If the OTA,
fingerprint, kernel, or payload hash changes, the watchdog refuses to run until
the port is revalidated and its allowlist is deliberately updated.
