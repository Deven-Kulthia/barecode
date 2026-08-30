#!/usr/bin/env bash
# Reproducible demo scenario for the 5-minute video.
#
#   ./scripts/demo.sh setup     build a victim venv with a real package in it
#   ./scripts/demo.sh poison    alter one character, preserving file size
#   ./scripts/demo.sh restore   undo the tampering
#   ./scripts/demo.sh clean     delete the venv
#
# Keeping this in a script means the demo is identical every take, and a judge
# can reproduce the wow moment themselves.
#
# This script is DEV TOOLING. It is not part of the shipped artifact, it is not
# imported by anything in src/, and BareCode itself never shells out.

set -euo pipefail

VENV="${VENV:-/tmp/barecode-demo}"
PKG="requests"
BC="./dist/barecode.pyz"

site_packages() { echo "$VENV"/lib/python*/site-packages; }
target() { echo "$(site_packages)/$PKG/sessions.py"; }

case "${1:-}" in
setup)
  rm -rf "$VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q "$PKG"
  make build >/dev/null
  echo "ready: $VENV  ($("$VENV/bin/pip" list --format=freeze | wc -l | tr -d ' ') packages)"
  echo "try:   $BC audit -p $VENV"
  ;;

poison)
  f="$(target)"
  cp "$f" "$f.orig"
  python3 - "$f" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
b = p.read_bytes()
i = b.find(b"HTTPAdapter")
assert i > 0, "anchor not found; pick another token"
# One character changed. Same byte count, so size and mtime look untouched.
p.write_bytes(b[:i] + b"HTTPAdaptor" + b[i + len(b"HTTPAdapter"):])
print(f"altered 1 character in {p.name}; size unchanged: {len(b)} bytes")
PY
  echo "now run: $BC verify -p $VENV"
  ;;

restore)
  f="$(target)"
  [ -f "$f.orig" ] && mv "$f.orig" "$f" && echo "restored $(basename "$f")"
  ;;

clean)
  rm -rf "$VENV"
  echo "removed $VENV"
  ;;

*)
  sed -n '2,9p' "$0"
  exit 2
  ;;
esac
