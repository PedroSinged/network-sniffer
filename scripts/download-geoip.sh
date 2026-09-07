#!/usr/bin/env bash
# Download the MaxMind GeoLite2-City database used by the -geoip flag.
#
# Requires a free MaxMind account and a license key:
#   https://www.maxmind.com/en/geolite2/signup
#
# Usage:
#   MAXMIND_LICENSE_KEY=xxxx ./scripts/download-geoip.sh [dest_dir]

set -euo pipefail

DEST_DIR="${1:-.}"
KEY="${MAXMIND_LICENSE_KEY:-}"

if [[ -z "$KEY" ]]; then
  echo "error: set MAXMIND_LICENSE_KEY (see script header)" >&2
  exit 1
fi

url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${KEY}&suffix=tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading GeoLite2-City..."
curl -fsSL "$url" -o "$tmp/geoip.tar.gz"
tar -xzf "$tmp/geoip.tar.gz" -C "$tmp"

mmdb="$(find "$tmp" -name 'GeoLite2-City.mmdb' -print -quit)"
if [[ -z "$mmdb" ]]; then
  echo "error: GeoLite2-City.mmdb not found in archive" >&2
  exit 1
fi

mkdir -p "$DEST_DIR"
cp "$mmdb" "$DEST_DIR/GeoLite2-City.mmdb"
echo "saved $DEST_DIR/GeoLite2-City.mmdb"
echo "run: network-sniffer -i eth0 -geoip $DEST_DIR/GeoLite2-City.mmdb"
