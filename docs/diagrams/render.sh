#!/usr/bin/env bash
#
# Regenerate the README diagrams from the .html sources in this folder.
#
# Renders each self-contained HTML file to a high-DPI PNG with headless Chrome,
# then auto-crops the surrounding background with Pillow so the image is tight.
#
# Requirements:
#   - Google Chrome (macOS path below; override with CHROME=...)
#   - python3 with Pillow  (pip install pillow)
#
# Usage:  ./docs/diagrams/render.sh          # run from the repo root
#
set -uo pipefail

CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$(cd "${DIR}/.." && pwd)/images"
mkdir -p "${OUT}"

# name  width  (height is generous; the crop step trims it)
DIAGRAMS=(
  "architecture 1320 1050"
  "flow-deterministic-confirm 1080 1000"
  "flow-false-positive 1080 1050"
  "flow-adaptive-sqli 1120 1700"
)

enc(){ python3 -c "import urllib.parse,os,sys;print('file://'+urllib.parse.quote(os.path.abspath(sys.argv[1])))" "$1"; }

for spec in "${DIAGRAMS[@]}"; do
  read -r name w h <<< "$spec"
  out="${OUT}/${name}.png"; prof="$(mktemp -d)"; rm -f "$out"
  "${CHROME}" --headless=new --disable-gpu --hide-scrollbars --no-first-run \
    --no-default-browser-check --disable-extensions --disable-background-networking \
    --mute-audio --force-device-scale-factor=2 --user-data-dir="${prof}" \
    --window-size="${w},${h}" --screenshot="${out}" "$(enc "${DIR}/${name}.html")" \
    >/dev/null 2>&1 &
  cpid=$!
  # headless Chrome writes the screenshot but does not always self-exit; wait
  # for the file, then stop it.
  for _ in $(seq 1 50); do [ -s "${out}" ] && { sleep 0.6; break; }; sleep 0.3; done
  kill "${cpid}" 2>/dev/null; wait "${cpid}" 2>/dev/null
  echo "rendered ${name}.png"
done
pkill -f "headless=new" 2>/dev/null || true

python3 - "${OUT}" <<'PY'
import sys, glob, os
from PIL import Image, ImageChops
BG=(13,17,23); MARGIN=56  # 28px @2x device scale
for p in sorted(glob.glob(os.path.join(sys.argv[1], "*.png"))):
    im=Image.open(p).convert("RGB")
    bbox=ImageChops.difference(im, Image.new("RGB", im.size, BG)).getbbox()
    if not bbox:
        continue
    new_h=min(im.height, bbox[3]+MARGIN)
    im.crop((0,0,im.width,new_h)).save(p)
    print(f"cropped {os.path.basename(p)} -> {im.width}x{new_h}")
PY

# ---- animated GIF: progressive reveal of the adaptive SQLi flow ------------
FRAMES="$(mktemp -d)"
for n in $(seq 1 11); do
  out="${FRAMES}/f$(printf '%02d' "$n").png"
  "${CHROME}" --headless=new --disable-gpu --hide-scrollbars --no-first-run \
    --no-default-browser-check --disable-extensions --disable-background-networking \
    --mute-audio --force-device-scale-factor=1 --user-data-dir="$(mktemp -d)" \
    --window-size=1120,1150 --screenshot="${out}" \
    "$(enc "${DIR}/anim-adaptive-sqli.html")?n=${n}" >/dev/null 2>&1 &
  cpid=$!
  for _ in $(seq 1 40); do [ -s "${out}" ] && { sleep 0.4; break; }; sleep 0.25; done
  kill "${cpid}" 2>/dev/null; wait "${cpid}" 2>/dev/null
done
pkill -f "headless=new" 2>/dev/null || true

python3 - "${FRAMES}" "${OUT}/adaptive-sqli.gif" <<'PY'
import sys, glob
from PIL import Image, ImageChops
BG=(13,17,23); MARGIN=28
frames=[Image.open(p).convert("RGB") for p in sorted(glob.glob(sys.argv[1] + "/f*.png"))]
bbox=ImageChops.difference(frames[-1], Image.new("RGB", frames[-1].size, BG)).getbbox()
crop=(0, 0, frames[-1].width, min(frames[-1].height, bbox[3] + MARGIN))
frames=[f.crop(crop) for f in frames]
pal=frames[-1].quantize(colors=200, method=Image.MEDIANCUT)          # shared palette
q=[f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]  # no flicker
q[0].save(sys.argv[2], save_all=True, append_images=q[1:],
          duration=[650] * (len(q) - 1) + [3000], loop=0, optimize=True, disposal=1)
print("rendered adaptive-sqli.gif")
PY
