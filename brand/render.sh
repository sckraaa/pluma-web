#!/usr/bin/env bash
# Renders the Pluma icons and logos of the web client from the SVGs in
# brand/src into brand/web, at the paths of upstream's public/ they replace:
# ci/patch.py copies them over upstream's files (ICONS) and
# ci/check_bundle.py finds them in the site. Run it after changing an SVG
# and commit what it writes; it prints the SHA-256 of every file.
#
# Sources: pluma-icon.svg, pluma-icon-square.svg, pluma-mark.svg and
# pluma-mark-mono.svg come from the owner's brand kit as they are;
# pluma-favicon.svg (the mark on a tight plate, readable at 16 px) and
# pluma-qr-logo.svg (the mark on a white disc, for the middle of a QR code)
# are derived from pluma-mark.svg.
#
# Needs rsvg-convert (librsvg) and ImageMagick 7 (magick).
set -euo pipefail
cd "$(dirname "$0")"

src=src
out=web/assets/img
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

rm -rf web
mkdir -p "$out"

# magick args... out: a PNG without time stamps, so a render of the same
# SVGs is the same bytes.
png() {
	magick "${@:1:$#-1}" -strip -define png:exclude-chunks=date,time "${!#}"
}

# svg width height out: an SVG rendered at a size, with transparency.
render() {
	rsvg-convert -w "$2" -h "$3" -o "$4" "$1"
}

# The app icon: the mark on a white rounded square.
for size in 36 48 72 96 144 192 256 384 512; do
	render "$src/pluma-icon.svg" "$size" "$size" "$out/android-chrome-${size}x${size}.png"
done
render "$src/pluma-icon.svg" 180 180 "$out/apple-touch-icon-precomposed.png"
render "$src/pluma-icon.svg" 194 194 "$out/favicon-194x194.png"
render "$src/pluma-icon.svg" 512 512 "$out/logo_filled_rounded.png"
render "$src/pluma-icon.svg" 512 512 "$out/logo_512.png"

# iOS rounds the corners itself: the square icon, opaque.
render "$src/pluma-icon-square.svg" 180 180 "$tmp/apple.png"
png "$tmp/apple.png" -background white -alpha remove -alpha off "$out/apple-touch-icon.png"

# Favicons: the tight plate.
for size in 16 32 48; do
	render "$src/pluma-favicon.svg" "$size" "$size" "$tmp/favicon-$size.png"
done
cp "$tmp/favicon-16.png" "$out/favicon-16x16.png"
cp "$tmp/favicon-32.png" "$out/favicon-32x32.png"
# Upstream's favicon_unread.ico is a 32 px PNG under that name; nothing
# references it.
cp "$tmp/favicon-32.png" "$out/favicon_unread.ico"
magick "$tmp/favicon-16.png" "$tmp/favicon-32.png" "$tmp/favicon-48.png" "$out/favicon.ico"

# Safari's installed web app (site_apple.webmanifest): the icon on a
# transparent canvas with a soft shadow, as macOS draws app icons.
for size in 192 384 512; do
	plate=$((size * 86 / 100))
	blur=$((size / 64))
	render "$src/pluma-icon.svg" "$plate" "$plate" "$tmp/plate.png"
	png -size "${size}x${size}" xc:none \
		\( "$tmp/plate.png" -background black -shadow "25x${blur}+0+$((blur / 2))" \) \
		-gravity center -composite \
		"$tmp/plate.png" -gravity center -composite \
		"$out/icon_square_${size}.png"
done

# Windows tiles: the mark in white on transparent (the tile colour is
# behind it), sized and placed as upstream's: width height box centre-x
# centre-y name.
render "$src/pluma-mark-mono.svg" 784 672 "$tmp/mark.png"
png "$tmp/mark.png" -channel RGB -evaluate set 100% +channel "$tmp/mark-white.png"
tile() {
	local w=$1 h=$2 box=$3 cx=$4 cy=$5 name=$6
	local mh=$((box * 336 / 392))
	png -size "${w}x${h}" xc:none \
		\( "$tmp/mark-white.png" -resize "${box}x${mh}" \) \
		-gravity northwest -geometry "+$((cx - box / 2))+$((cy - mh / 2))" -composite \
		"$out/$name"
}
tile 128 128 96 64 64 mstile-70x70.png
tile 144 144 100 72 72 mstile-144x144.png
tile 270 270 126 135 113 mstile-150x150.png
tile 558 558 259 279 258 mstile-310x310.png
tile 558 270 126 279 113 mstile-310x150.png

# SVGs the client loads as they are.
cp "$src/pluma-qr-logo.svg" "$out/logo_padded.svg"
cp "$src/pluma-mark-mono.svg" "$out/logo_plain.svg"
cp "$src/pluma-icon.svg" "$out/logo.svg"
cp "$src/pluma-icon.svg" "$out/logo_filled.svg"
cp "$src/pluma-mark-mono.svg" "$out/safari-pinned-tab.svg"
cp "$src/pluma-mark-mono.svg" "$out/masked.svg"
cp "$src/pluma-mark-mono.svg" "$out/masked copy.svg"

(cd web && find . -type f | sort | sed 's|^\./||' | while read -r f; do
	printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"
done)
