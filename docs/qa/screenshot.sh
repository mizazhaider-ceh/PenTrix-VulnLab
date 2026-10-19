#!/usr/bin/env bash
# screenshot.sh: render a local page to PNG without a browser.
# Pipeline: curl page HTML -> inline linked CSS -> WeasyPrint PDF -> pdftoppm PNG.
# (Meta Chromium on this VM blocks localhost via Local Network Access checks,
#  so this is the working visual-verification pipeline.)
#
# Usage: ./screenshot.sh <url> <name> [outdir]
# Example: ./screenshot.sh http://localhost:3000/ home
# Output: <outdir>/<name>.png (first page only, 60 dpi)
#
# Only ever point this at the local lab instance. Never expose the lab publicly.
set -euo pipefail

URL="${1:?usage: screenshot.sh <url> <name> [outdir]}"
NAME="${2:?usage: screenshot.sh <url> <name> [outdir]}"
OUTDIR="${3:-/tmp/pentrix-shots}"
BASE="$(printf '%s' "$URL" | sed -E 's#(https?://[^/]+).*#\1#')"

mkdir -p "$OUTDIR"
HTML="$OUTDIR/$NAME.raw.html"
PDF="$OUTDIR/$NAME.pdf"
PNG="$OUTDIR/$NAME.png"

curl -sS --max-time 20 -o "$HTML" "$URL"

python3 - "$HTML" "$BASE" <<'EOF'
import re, sys, urllib.request
html_path, base = sys.argv[1], sys.argv[2]
html = open(html_path, encoding='utf-8', errors='replace').read()

def inline_css(m):
    href = m.group(1)
    css_url = href if href.startswith('http') else base + (href if href.startswith('/') else '/' + href)
    try:
        css = urllib.request.urlopen(css_url, timeout=15).read().decode('utf-8', errors='replace')
        return '<style>\n' + css + '\n</style>'
    except Exception as e:
        return '<!-- css fetch failed: %s -->' % e

html = re.sub(r'<link[^>]+rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*>', inline_css, html, flags=re.I)
html = re.sub(r'<link[^>]+href=["\']([^"\']+\.css)["\'][^>]*>', inline_css, html, flags=re.I)
open(html_path, 'w', encoding='utf-8').write(html)
EOF

if ! python3 -m weasyprint "$HTML" "$PDF" 2>"$OUTDIR/$NAME.weasy.log"; then
  echo "weasyprint failed, see $OUTDIR/$NAME.weasy.log"
  exit 1
fi
pdftoppm -png -r 60 -f 1 -l 1 "$PDF" "$OUTDIR/$NAME.page"
produced="$(ls "$OUTDIR/$NAME.page-"*.png 2>/dev/null | head -1)"
if [ -z "$produced" ]; then
  echo "pdftoppm produced no PNG"
  exit 1
fi
mv "$produced" "$PNG"
echo "wrote $PNG"
