#!/usr/bin/env bash
set -euo pipefail

# Generate Windows .ico files from the project SVG icons using ImageMagick (Linux/macOS)
#
# Usage:
#   bash tools/make_icons.sh
#
# Requirements:
#   - ImageMagick installed and on PATH (either `magick` or `convert` binary)

project_root="$(cd "$(dirname "$0")/.." && pwd)"

# Pick ImageMagick entrypoint
if command -v magick >/dev/null 2>&1; then
  IM="magick"
elif command -v convert >/dev/null 2>&1; then
  IM="convert"
else
  echo "Error: ImageMagick not found (need 'magick' or 'convert' on PATH)" >&2
  exit 1
fi

echo "Using ImageMagick: $IM"

# icon specs
SIZES=(16 24 32 48 64 128 256)

declare -a ICONS=(
  "mdmcpsrvr:mdmcpsrvr/res/mdmcpsrvr.svg:mdmcpsrvr/res/mdmcpsrvr.ico"
  "mdmcpcfg:mdmcpcfg/res/mdmcpcfg.svg:mdmcpcfg/res/mdmcpcfg.ico"
)

for spec in "${ICONS[@]}"; do
  IFS=":" read -r name svg rel_ico <<<"$spec"

  svg_path="$project_root/$svg"
  out_dir="$(dirname "$project_root/$rel_ico")"
  ico_path="$project_root/$rel_ico"

  if [[ ! -f "$svg_path" ]]; then
    echo "Warning: SVG not found: $svg_path (skipping $name)" >&2
    continue
  fi

  mkdir -p "$out_dir"
  tmpdir="$(mktemp -d)"

  pngs=()
  for s in "${SIZES[@]}"; do
    png="$tmpdir/${name}-${s}.png"
    # Render SVG to PNG at target size with alpha transparency
    # -density helps with SVG rasterization quality; adjust as needed.
    $IM -background none -density 512 "$svg_path" -resize ${s}x${s} "$png"
    pngs+=("$png")
  done

  # Assemble multi-size ICO
  $IM "${pngs[@]}" "$ico_path"
  echo "Created: $ico_path"

  rm -rf "$tmpdir"
done

echo "Done. Rebuild on Windows to embed the icons into the executables."

