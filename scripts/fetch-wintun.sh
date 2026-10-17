#!/usr/bin/env bash
# Downloads Wintun (https://www.wintun.net), the TUN driver the Windows agent
# loads, verifies it against a pinned checksum and unpacks the DLLs into
# build/wintun/<goarch>/wintun.dll. The Windows release archives ship it next
# to transporter.exe; it is redistributable under its own license (included).
set -euo pipefail

version=0.14.1
sha256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
out=${1:-build/wintun}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/wintun.zip" "https://www.wintun.net/builds/wintun-$version.zip"
if command -v sha256sum >/dev/null; then
  got=$(sha256sum "$tmp/wintun.zip" | cut -d' ' -f1)
else
  got=$(shasum -a 256 "$tmp/wintun.zip" | cut -d' ' -f1)
fi
if [[ $got != "$sha256" ]]; then
  echo "wintun-$version.zip checksum mismatch: got $got" >&2
  exit 1
fi
unzip -q "$tmp/wintun.zip" -d "$tmp"
for arch in amd64 arm64; do
  mkdir -p "$out/$arch"
  cp "$tmp/wintun/bin/$arch/wintun.dll" "$out/$arch/"
  cp "$tmp/wintun/LICENSE.txt" "$out/$arch/wintun-LICENSE.txt"
done
echo "wintun $version -> $out"
