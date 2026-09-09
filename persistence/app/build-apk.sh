#!/bin/sh

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
APP="$ROOT/persistence/app"
BUILD="$APP/build"
PAYLOAD="$ROOT/exploit/build/preload-mdarcy-9.2.4.so"
RUNNER="$BUILD/libghostlock_runner.so"
KEYSTORE=${GHOSTLOCK_KEYSTORE:?set GHOSTLOCK_KEYSTORE}
KEY_PASSWORD_FILE=${GHOSTLOCK_KEY_PASSWORD_FILE:?set GHOSTLOCK_KEY_PASSWORD_FILE}
KEY_ALIAS=${GHOSTLOCK_KEY_ALIAS:-ghostlock-boot}

[ -f "$PAYLOAD" ] || { echo "missing payload: $PAYLOAD" >&2; exit 1; }
[ -f "$RUNNER" ] || { echo "missing runner: $RUNNER" >&2; exit 1; }
[ -f "$KEYSTORE" ] || { echo "missing keystore: $KEYSTORE" >&2; exit 1; }
[ -f "$KEY_PASSWORD_FILE" ] || {
  echo "missing keystore password file: $KEY_PASSWORD_FILE" >&2
  exit 1
}

rm -rf "$BUILD/apk"
mkdir -p "$BUILD/apk/staging/lib/arm64-v8a"

smali assemble "$APP/smali" -o "$BUILD/apk/staging/classes.dex"
aapt package -f \
  -M "$APP/AndroidManifest.xml" \
  -I /usr/share/android-framework-res/framework-res.apk \
  -F "$BUILD/apk/manifest.apk"

cp "$RUNNER" "$BUILD/apk/staging/lib/arm64-v8a/libghostlock_runner.so"
cp "$PAYLOAD" "$BUILD/apk/staging/lib/arm64-v8a/libghostlock.so"
cp "$BUILD/apk/manifest.apk" "$BUILD/apk/unsigned.apk"
(
  cd "$BUILD/apk/staging"
  aapt add "$BUILD/apk/unsigned.apk" \
    classes.dex \
    lib/arm64-v8a/libghostlock_runner.so \
    lib/arm64-v8a/libghostlock.so
)

zipalign -f 4 "$BUILD/apk/unsigned.apk" "$BUILD/apk/aligned.apk"
apksigner sign \
  --ks "$KEYSTORE" \
  --ks-key-alias "$KEY_ALIAS" \
  --ks-pass "file:$KEY_PASSWORD_FILE" \
  --key-pass "file:$KEY_PASSWORD_FILE" \
  --out "$BUILD/ghostlock-boot-mdarcy-9.2.4.apk" \
  "$BUILD/apk/aligned.apk"
apksigner verify --verbose "$BUILD/ghostlock-boot-mdarcy-9.2.4.apk"
