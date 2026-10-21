#!/bin/sh
# Assemble the dev.rtrdd.ipatool rootless .deb from an already-built,
# ldid-signed ipatool binary. Usage: build-deb.sh <binary> <version> <out.deb>
set -eu
BIN=$1; VERSION=$2; OUT=$3
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PKG=$(mktemp -d)
trap 'rm -rf "$PKG"' EXIT

install -d "$PKG/DEBIAN" "$PKG/var/jb/usr/local/bin" "$PKG/var/jb/usr/share/doc/dev.rtrdd.ipatool"
sed "s/@VERSION@/$VERSION/" "$ROOT/packaging/ipatool/control" > "$PKG/DEBIAN/control"
install -m 0755 "$BIN" "$PKG/var/jb/usr/local/bin/ipatool"
install -m 0644 "$ROOT/LICENSE" "$PKG/var/jb/usr/share/doc/dev.rtrdd.ipatool/LICENSE"
printf 'Upstream: https://github.com/majd/ipatool (MIT)\nFork: https://github.com/aayy-dev/ipatool\n' \
  > "$PKG/var/jb/usr/share/doc/dev.rtrdd.ipatool/copyright"
size=$(du -sk "$PKG/var" | cut -f1)
echo "Installed-Size: $size" >> "$PKG/DEBIAN/control"
find "$PKG" -name .DS_Store -delete
dpkg-deb -Zxz --root-owner-group -b "$PKG" "$OUT"
