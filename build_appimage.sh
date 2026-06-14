#!/usr/bin/env sh
set -eu
APPDIR="${1:-privacy-index-v3.4.AppDir}"
OUT="${2:-PrivacyIndex-v3.4-x86_64.AppImage}"
if ! command -v appimagetool >/dev/null 2>&1; then
  echo "appimagetool introuvable. Installe appimagetool, puis relance:" >&2
  echo "  ARCH=x86_64 appimagetool \"$APPDIR\" \"$OUT\"" >&2
  exit 1
fi
ARCH=x86_64 appimagetool "$APPDIR" "$OUT"
chmod +x "$OUT"
