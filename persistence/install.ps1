param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [string]$AdbPath = 'adb',
    [long]$LastAttemptEpoch = 0
)

$ErrorActionPreference = 'Stop'

$expectedDevice = 'mdarcy'
$expectedFingerprint = 'NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4387.0822:user/release-keys'
$expectedKernel = '4.9.141-tegra-gb6e5605a'
$expectedApkSha256 = '5ced50985a40063f8d3a0d9497b5b850b7e085fac2c35b028956dcfaf99e9495'
$package = 'com.cyberbalsa.ghostlockboot'
$apk = Join-Path $PSScriptRoot 'app/build/ghostlock-boot-mdarcy-9.2.4.apk'

if (-not (Test-Path -LiteralPath $apk -PathType Leaf)) {
    throw "Required APK is missing: $apk"
}
$apkHash = (Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant()
if ($apkHash -ne $expectedApkSha256) {
    throw "APK hash mismatch: $apkHash"
}

& $AdbPath connect $Target | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'adb connect failed' }

$device = (& $AdbPath -s $Target shell getprop ro.product.device).Trim()
$fingerprint = (& $AdbPath -s $Target shell getprop ro.build.fingerprint).Trim()
$kernel = (& $AdbPath -s $Target shell uname -r).Trim()
if ($device -ne $expectedDevice -or
    $fingerprint -ne $expectedFingerprint -or
    $kernel -ne $expectedKernel) {
    throw "Target mismatch: device=$device fingerprint=$fingerprint kernel=$kernel"
}

# Android can redeliver BOOT_COMPLETED after replacing an installed package.
# If this is an upgrade, stop and disable the old copy before adb install so a
# replacement broadcast cannot race state seeding. A fresh install begins in
# Android's stopped state and cannot receive the broadcast until the activity
# below deliberately clears that flag.
$existingPath = (& $AdbPath -s $Target shell pm path $package 2>$null).Trim()
if ($existingPath -match '^package:') {
    & $AdbPath -s $Target shell am force-stop $package
    & $AdbPath -s $Target shell run-as $package mkdir -p files
    if ($LASTEXITCODE -ne 0) { throw 'could not access existing app state' }
    & $AdbPath -s $Target shell run-as $package touch files/DISABLED
    if ($LASTEXITCODE -ne 0) { throw 'could not disable existing boot runner' }
}

& $AdbPath -s $Target install -r -g $apk | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'APK installation failed' }

# Keep the boot runner transactionally disabled while its state is seeded and
# Android's newly-installed/stopped package state is cleared.
& $AdbPath -s $Target shell run-as $package mkdir -p files
if ($LASTEXITCODE -ne 0) { throw 'could not create app state directory' }
& $AdbPath -s $Target shell run-as $package touch files/DISABLED
if ($LASTEXITCODE -ne 0) { throw 'could not create app disable marker' }

$bootCount = (& $AdbPath -s $Target shell settings get global boot_count).Trim()
if ($bootCount -notmatch '^\d+$') {
    throw "Android returned an invalid boot count: $bootCount"
}
$seedEpoch = if ($LastAttemptEpoch -gt 0) {
    $LastAttemptEpoch
} else {
    [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}
$stateCommand = "run-as $package sh -c 'printf `"boot_count=%s\nlast_attempt_epoch=%s\n`" `"$bootCount`" `"$seedEpoch`" > files/watchdog.state'"
& $AdbPath -s $Target shell $stateCommand
if ($LASTEXITCODE -ne 0) { throw 'could not seed app watchdog state' }
& $AdbPath -s $Target shell run-as $package chmod 0600 files/DISABLED files/watchdog.state
if ($LASTEXITCODE -ne 0) { throw 'could not protect app watchdog state' }

& $AdbPath -s $Target shell am force-stop $package
& $AdbPath -s $Target shell am start -n "$package/.BootstrapActivity" | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'could not clear Android package stopped state' }
Start-Sleep -Seconds 2

& $AdbPath -s $Target shell run-as $package rm -f files/DISABLED
if ($LASTEXITCODE -ne 0) { throw 'could not arm the boot runner' }

Write-Host "Installed and armed for the next boot (boot_count=$bootCount, last_attempt_epoch=$seedEpoch)."
