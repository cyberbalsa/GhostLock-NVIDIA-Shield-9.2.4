param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [string]$AdbPath = 'adb'
)

$ErrorActionPreference = 'Stop'
$package = 'com.cyberbalsa.ghostlockboot'

& $AdbPath connect $Target | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'adb connect failed' }
& $AdbPath -s $Target shell am force-stop $package
& $AdbPath -s $Target uninstall $package | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'APK uninstall failed' }

Write-Host 'Removed the on-device GhostLock boot app and its private state.'
