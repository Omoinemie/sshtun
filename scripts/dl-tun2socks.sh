#!/bin/sh
# dl-tun2socks.sh - download the latest tun2socks into the current directory (Linux / macOS).
#
# Usage:
#   sh dl-tun2socks.sh
#
# After unpacking, the current directory contains tun2socks, which is where
# sshtun looks for it first.
#
# Environment variables:
#   T2S_VERSION   pin a version (e.g. v2.7.0). Empty = latest.
#   GH_MIRROR     GitHub mirror prefix (e.g. https://ghfast.top). Several may be
#                 given, separated by spaces, and are tried in order.
#
# Notes:
#   This script is for Linux: it only downloads tun2socks.
#   Linux uses the kernel TUN device and does not need wintun.dll (that is a
#   Windows driver). Windows users should use dl-tun2socks.bat instead.

REPO=xjasonlyu/tun2socks
API="https://api.github.com/repos/$REPO/releases/latest"
GHDL="https://github.com/$REPO/releases/download"
MIRRORS="${GH_MIRROR:-https://ghfast.top https://ghproxy.net https://gh-proxy.com}"

die() {
	echo "Error: $*" >&2
	exit 1
}

# ---------- 1. local version ----------
LOCAL=""
if [ -x ./tun2socks ]; then
	LOCAL=$(./tun2socks --version 2>/dev/null | head -1 | sed 's/^tun2socks-//')
fi

# ---------- 2. latest version ----------
TAG=""
if [ -n "${T2S_VERSION:-}" ]; then
	TAG="$T2S_VERSION"
else
	TAG=$(curl -fsSL --connect-timeout 20 "$API" 2>/dev/null |
		sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
	if [ -z "$TAG" ]; then
		# The API is unreachable: fall back to the 302 redirect of
		# releases/latest and take the last path segment.
		LOC=$(curl -fsSI --connect-timeout 20 "$GHDL/latest" 2>/dev/null |
			tr -d '\r' | sed -n 's/^[Ll]ocation:[[:space:]]*//p' | head -1)
		case "$LOC" in
		*/tag/*) TAG=${LOC##*/tag/} ;;
		esac
	fi
	[ -n "$TAG" ] || die "cannot resolve the latest version (set T2S_VERSION to pin one)"
fi
case "$TAG" in v*) ;; *) TAG="v$TAG" ;; esac
LATEST="${TAG#v}"

# ---------- 3. compare the versions ----------
if [ "$LOCAL" = "$LATEST" ]; then
	echo "tun2socks is already at the latest version v$LATEST, nothing to download"
	exit 0
fi
echo "tun2socks v${LOCAL:-none} -> v$LATEST"

# ---------- 4. download ----------
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
linux | darwin) ;;
*) die "this script is for Linux, use dl-tun2socks.bat on Windows" ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported architecture: $(uname -m)" ;;
esac
ASSET="tun2socks-$OS-$ARCH.zip"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
ZIP="$TMP/$ASSET"

URLS="$GHDL/$TAG/$ASSET"
for m in $MIRRORS; do
	URLS="$URLS $m/$GHDL/$TAG/$ASSET"
done

DOWNLOADED=""
for url in $URLS; do
	echo "Downloading $url"
	if curl -fsSL --connect-timeout 20 --max-time 900 -o "$ZIP" "$url"; then
		DOWNLOADED=1
		break
	fi
	echo "   failed, trying the next source"
done
[ -n "$DOWNLOADED" ] || die "failed to download tun2socks, check the network or set GH_MIRROR"

# ---------- 5. unpack into the current directory ----------
echo "Unpacking"
if command -v unzip >/dev/null 2>&1; then
	unzip -oq "$ZIP" -d "$TMP/x"
elif command -v bsdtar >/dev/null 2>&1; then
	bsdtar -xf "$ZIP" -C "$TMP/x"
else
	die "unzip or bsdtar is required to unpack the zip"
fi

BIN=$(find "$TMP/x" -type f -name 'tun2socks-*' | head -n1)
[ -n "$BIN" ] || die "no tun2socks executable found in the archive"

cp -f "$BIN" ./tun2socks
chmod +x ./tun2socks

echo "Done: $(pwd)/tun2socks"
