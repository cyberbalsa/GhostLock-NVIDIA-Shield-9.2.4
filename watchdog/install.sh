#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 HOST:PORT" >&2
  exit 2
fi

shield_target=$1
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
payload_source=${GHOSTLOCK_PAYLOAD_SOURCE:-$repository_dir/exploit/build/preload-mdarcy-9.2.4.so}
expected_hash=a3a1e75b627d8dd419e9bafd2a73082a8647510bf6ce4f975e52baf5aa1d0761
actual_hash=$(sha256sum "$payload_source" | awk '{print $1}')

if [ "$actual_hash" != "$expected_hash" ]; then
  echo "payload hash mismatch: expected $expected_hash, got $actual_hash" >&2
  exit 1
fi
if [ ! -f "$HOME/.android/adbkey" ]; then
  echo "missing $HOME/.android/adbkey; authorize this host with the Shield first" >&2
  exit 1
fi

config_dir=$HOME/.config/ghostlock-shield
quadlet_dir=$HOME/.config/containers/systemd
payload_dir=$HOME/.local/share/ghostlock-shield/payload
state_dir=$HOME/.local/share/ghostlock-shield/state
mkdir -p "$config_dir" "$quadlet_dir" "$payload_dir" "$state_dir"
install -m 0644 "$payload_source" "$payload_dir/preload-mdarcy-9.2.4.so"
install -m 0644 "$script_dir/ghostlock-shield-watchdog.container" \
  "$quadlet_dir/ghostlock-shield-watchdog.container"

env_file=$config_dir/watchdog.env
umask 077
{
  printf 'SHIELD_ADB_TARGET=%s\n' "$shield_target"
  printf 'SHIELD_EXPECTED_FINGERPRINT=%s\n' \
    'NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4387.0822:user/release-keys'
  printf 'SHIELD_EXPECTED_KERNEL=%s\n' '4.9.141-tegra-gb6e5605a'
  printf 'GHOSTLOCK_PAYLOAD_SHA256=%s\n' "$expected_hash"
  printf 'WATCHDOG_CHECK_INTERVAL=30\n'
  printf 'WATCHDOG_MIN_ATTEMPT_INTERVAL=900\n'
  printf 'WATCHDOG_MAX_ATTEMPTS_PER_BOOT=2\n'
} > "$env_file"

podman build -t localhost/ghostlock-shield-watchdog:9.2.4 \
  -f "$script_dir/Containerfile" "$repository_dir"
systemctl --user daemon-reload
systemctl --user start ghostlock-shield-watchdog.service
echo "installed: systemctl --user status ghostlock-shield-watchdog.service"
