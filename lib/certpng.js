// PenTrix VulnLab: zero-dependency PNG certificate renderer.
// Pure Node.js: pixel buffer, hand-authored 5x7 bitmap font, PNG encoder.
// No npm packages, no native modules, no child processes.
// NOTE: never use em dashes in code, comments, or certificate text.

'use strict';

const zlib = require('zlib');

const W = 1200;
const H = 850;

// ---------------------------------------------------------------------------
// Palette (light clay style)
// ---------------------------------------------------------------------------
const C = {
  bg: [244, 241, 250],        // #F4F1FA lavender background
  violet: [123, 97, 201],     // #7B61C9 accents
  deepViolet: [90, 72, 168],  // #5A48A8 borders
  pink: [246, 174, 203],      // #F6AECB accents
  orbLight: [208, 198, 242],  // light violet orb
  orbPink: [247, 202, 224],   // light pink orb
  ink: [43, 39, 64],          // #2B2740 main text
  muted: [110, 104, 144],     // #6E6890 secondary text
  white: [255, 255, 255],
};

// ---------------------------------------------------------------------------
// 5x7 bitmap font. Each glyph is 7 rows of 5 cells ('#' = ink, '.' = empty).
// Authored for this file: A-Z, a-z, 0-9, space, and . , : - / ( ) ! ' { } @ ?
// < > ; = " + _ * [ ] # % & $ ~ ^ | backslash backtick.
// ---------------------------------------------------------------------------
const FONT = {
  'A': ['.###.', '#...#', '#...#', '#####', '#...#', '#...#', '#...#'],
  'B': ['####.', '#...#', '#...#', '####.', '#...#', '#...#', '####.'],
  'C': ['.####', '#....', '#....', '#....', '#....', '#....', '.####'],
  'D': ['####.', '#...#', '#...#', '#...#', '#...#', '#...#', '####.'],
  'E': ['#####', '#....', '#....', '####.', '#....', '#....', '#####'],
  'F': ['#####', '#....', '#....', '####.', '#....', '#....', '#....'],
  'G': ['.####', '#....', '#....', '#.###', '#...#', '#...#', '.###.'],
  'H': ['#...#', '#...#', '#...#', '#####', '#...#', '#...#', '#...#'],
  'I': ['#####', '..#..', '..#..', '..#..', '..#..', '..#..', '#####'],
  'J': ['..###', '...#.', '...#.', '...#.', '...#.', '#..#.', '.##..'],
  'K': ['#...#', '#..#.', '#.#..', '##...', '#.#..', '#..#.', '#...#'],
  'L': ['#....', '#....', '#....', '#....', '#....', '#....', '#####'],
  'M': ['#...#', '##.##', '#.#.#', '#.#.#', '#...#', '#...#', '#...#'],
  'N': ['#...#', '##..#', '##..#', '#.#.#', '#..##', '#..##', '#...#'],
  'O': ['.###.', '#...#', '#...#', '#...#', '#...#', '#...#', '.###.'],
  'P': ['####.', '#...#', '#...#', '####.', '#....', '#....', '#....'],
  'Q': ['.###.', '#...#', '#...#', '#...#', '#.#.#', '#..#.', '.##.#'],
  'R': ['####.', '#...#', '#...#', '####.', '#.#..', '#..#.', '#...#'],
  'S': ['.####', '#....', '#....', '.###.', '....#', '....#', '####.'],
  'T': ['#####', '..#..', '..#..', '..#..', '..#..', '..#..', '..#..'],
  'U': ['#...#', '#...#', '#...#', '#...#', '#...#', '#...#', '.###.'],
  'V': ['#...#', '#...#', '#...#', '#...#', '#...#', '.#.#.', '..#..'],
  'W': ['#...#', '#...#', '#...#', '#.#.#', '#.#.#', '##.##', '#...#'],
  'X': ['#...#', '#...#', '.#.#.', '..#..', '.#.#.', '#...#', '#...#'],
  'Y': ['#...#', '#...#', '.#.#.', '..#..', '..#..', '..#..', '..#..'],
  'Z': ['#####', '....#', '...#.', '..#..', '.#...', '#....', '#####'],
  'a': ['.....', '.....', '.###.', '....#', '.####', '#...#', '.###.'],
  'b': ['#....', '#....', '####.', '#...#', '#...#', '#...#', '####.'],
  'c': ['.....', '.....', '.####', '#....', '#....', '#....', '.####'],
  'd': ['....#', '....#', '.####', '#...#', '#...#', '#...#', '.####'],
  'e': ['.....', '.....', '.###.', '#...#', '#####', '#....', '.###.'],
  'f': ['..##.', '...#.', '...#.', '.###.', '...#.', '...#.', '...#.'],
  'g': ['.....', '.....', '.####', '#...#', '.####', '....#', '.###.'],
  'h': ['#....', '#....', '####.', '#...#', '#...#', '#...#', '#...#'],
  'i': ['..#..', '.....', '..#..', '..#..', '..#..', '..#..', '.###.'],
  'j': ['...#.', '.....', '...#.', '...#.', '...#.', '#..#.', '.##..'],
  'k': ['#....', '#....', '#..#.', '#.#..', '##...', '#.#..', '#..#.'],
  'l': ['..#..', '..#..', '..#..', '..#..', '..#..', '..#..', '..#..'],
  'm': ['.....', '.....', '##.#.', '#.#.#', '#.#.#', '#...#', '#...#'],
  'n': ['.....', '.....', '####.', '#...#', '#...#', '#...#', '#...#'],
  'o': ['.....', '.....', '.###.', '#...#', '#...#', '#...#', '.###.'],
  'p': ['.....', '.....', '####.', '#...#', '####.', '#....', '#....'],
  'q': ['.....', '.....', '.####', '#...#', '.####', '....#', '....#'],
  'r': ['.....', '.....', '#.##.', '##...', '#....', '#....', '#....'],
  's': ['.....', '.....', '.####', '#....', '.###.', '....#', '####.'],
  't': ['...#.', '...#.', '.###.', '...#.', '...#.', '...#.', '..##.'],
  'u': ['.....', '.....', '#...#', '#...#', '#...#', '#...#', '.###.'],
  'v': ['.....', '.....', '#...#', '#...#', '#...#', '.#.#.', '..#..'],
  'w': ['.....', '.....', '#...#', '#...#', '#.#.#', '##.##', '#...#'],
  'x': ['.....', '.....', '#...#', '.#.#.', '..#..', '.#.#.', '#...#'],
  'y': ['.....', '.....', '#...#', '#...#', '.####', '....#', '.###.'],
  'z': ['.....', '.....', '#####', '...#.', '..#..', '.#...', '#####'],
  '0': ['.###.', '#..##', '#.#.#', '#.#.#', '##..#', '#...#', '.###.'],
  '1': ['..#..', '.##..', '..#..', '..#..', '..#..', '..#..', '.###.'],
  '2': ['.###.', '#...#', '....#', '...#.', '..#..', '.#...', '#####'],
  '3': ['####.', '....#', '....#', '.###.', '....#', '....#', '####.'],
  '4': ['...#.', '..##.', '.#.#.', '#..#.', '#####', '...#.', '...#.'],
  '5': ['#####', '#....', '####.', '....#', '....#', '#...#', '.###.'],
  '6': ['.###.', '#....', '#....', '####.', '#...#', '#...#', '.###.'],
  '7': ['#####', '....#', '...#.', '..#..', '.#...', '.#...', '.#...'],
  '8': ['.###.', '#...#', '#...#', '.###.', '#...#', '#...#', '.###.'],
  '9': ['.###.', '#...#', '#...#', '.####', '....#', '....#', '.###.'],
  ' ': ['.....', '.....', '.....', '.....', '.....', '.....', '.....'],
  '.': ['.....', '.....', '.....', '.....', '.....', '.##..', '.##..'],
  ',': ['.....', '.....', '.....', '.....', '.##..', '.##..', '.#...'],
  ':': ['.....', '.##..', '.##..', '.....', '.##..', '.##..', '.....'],
  '-': ['.....', '.....', '.....', '#####', '.....', '.....', '.....'],
  '/': ['....#', '....#', '...#.', '..#..', '.#...', '#....', '#....'],
  '(': ['...#.', '..#..', '.#...', '.#...', '.#...', '..#..', '...#.'],
  ')': ['.#...', '..#..', '...#.', '...#.', '...#.', '..#..', '.#...'],
  '!': ['..#..', '..#..', '..#..', '..#..', '..#..', '.....', '..#..'],
  "'": ['..#..', '..#..', '.....', '.....', '.....', '.....', '.....'],
  '{': ['...#.', '..#..', '..#..', '.#...', '..#..', '..#..', '...#.'],
  '}': ['.#...', '..#..', '..#..', '...#.', '..#..', '..#..', '.#...'],
  '@': ['.###.', '#...#', '#.##.', '#.#.#', '#.##.', '#....', '.###.'],
  '?': ['.###.', '#...#', '....#', '...#.', '..#..', '.....', '..#..'],
  '<': ['..##.', '.#...', '#....', '#....', '#....', '.#...', '..##.'],
  '>': ['.##..', '...#.', '....#', '....#', '....#', '...#.', '.##..'],
  ';': ['.....', '.##..', '.....', '.....', '.##..', '.##..', '.#...'],
  '=': ['.....', '.....', '#####', '.....', '#####', '.....', '.....'],
  '"': ['.#.#.', '.#.#.', '.....', '.....', '.....', '.....', '.....'],
  '+': ['.....', '..#..', '..#..', '#####', '..#..', '..#..', '.....'],
  '_': ['.....', '.....', '.....', '.....', '.....', '.....', '#####'],
  '*': ['.....', '.#.#.', '..#..', '#####', '..#..', '.#.#.', '.....'],
  '[': ['.###.', '.#...', '.#...', '.#...', '.#...', '.#...', '.###.'],
  ']': ['.###.', '...#.', '...#.', '...#.', '...#.', '...#.', '.###.'],
  '#': ['.#.#.', '.#.#.', '#####', '.#.#.', '#####', '.#.#.', '.#.#.'],
  '%': ['##..#', '##.#.', '...#.', '..#..', '.#...', '.#.##', '#..##'],
  '&': ['.##..', '#..#.', '#.#..', '.#...', '#.#.#', '#..#.', '.##.#'],
  '$': ['..#..', '.####', '#.#..', '.###.', '..#.#', '####.', '..#..'],
  '~': ['.....', '.....', '.....', '.###.', '#...#', '.....', '.....'],
  '^': ['..#..', '.#.#.', '.....', '.....', '.....', '.....', '.....'],
  '|': ['..#..', '..#..', '..#..', '..#..', '..#..', '..#..', '..#..'],
  '\\': ['#....', '#....', '.#...', '..#..', '...#.', '....#', '....#'],
  '`': ['.#...', '..#..', '.....', '.....', '.....', '.....', '.....'],
};

const GLYPH_W = 5;
const GLYPH_H = 7;
const ADVANCE = 6; // glyph width + 1 cell spacing

// ---------------------------------------------------------------------------
// Pixel buffer helpers
// ---------------------------------------------------------------------------
function newCanvas() {
  const buf = Buffer.alloc(W * H * 4);
  for (let i = 0; i < buf.length; i += 4) {
    buf[i] = C.bg[0];
    buf[i + 1] = C.bg[1];
    buf[i + 2] = C.bg[2];
    buf[i + 3] = 255;
  }
  return buf;
}

function setPixel(buf, x, y, color) {
  if (x < 0 || y < 0 || x >= W || y >= H) return;
  const i = (y * W + x) * 4;
  buf[i] = color[0];
  buf[i + 1] = color[1];
  buf[i + 2] = color[2];
  buf[i + 3] = 255;
}

function fillRect(buf, x, y, w, h, color) {
  const x0 = Math.max(0, Math.floor(x));
  const y0 = Math.max(0, Math.floor(y));
  const x1 = Math.min(W, Math.ceil(x + w));
  const y1 = Math.min(H, Math.ceil(y + h));
  for (let yy = y0; yy < y1; yy++) {
    for (let xx = x0; xx < x1; xx++) {
      const i = (yy * W + xx) * 4;
      buf[i] = color[0];
      buf[i + 1] = color[1];
      buf[i + 2] = color[2];
    }
  }
}

function fillCircle(buf, cx, cy, r, color) {
  const rr = Math.floor(r);
  for (let dy = -rr; dy <= rr; dy++) {
    const dx = Math.floor(Math.sqrt(Math.max(0, rr * rr - dy * dy)));
    fillRect(buf, cx - dx, cy + dy, dx * 2 + 1, 1, color);
  }
}

function fillRoundedRect(buf, x, y, w, h, r, color) {
  const rad = Math.max(0, Math.min(r, Math.floor(Math.min(w, h) / 2)));
  fillRect(buf, x + rad, y, w - rad * 2, h, color);
  fillRect(buf, x, y + rad, w, h - rad * 2, color);
  fillCircle(buf, x + rad, y + rad, rad, color);
  fillCircle(buf, x + w - rad, y + rad, rad, color);
  fillCircle(buf, x + rad, y + h - rad, rad, color);
  fillCircle(buf, x + w - rad, y + h - rad, rad, color);
}

function outlineRoundedRect(buf, x, y, w, h, r, t, color, bgColor) {
  fillRoundedRect(buf, x, y, w, h, r, color);
  fillRoundedRect(buf, x + t, y + t, w - t * 2, h - t * 2, Math.max(0, r - t), bgColor);
}

// Thick line: stamp circles along the segment.
function thickLine(buf, x0, y0, x1, y1, w, color) {
  const steps = Math.max(Math.abs(x1 - x0), Math.abs(y1 - y0));
  const n = Math.max(1, steps);
  for (let i = 0; i <= n; i++) {
    const t = i / n;
    fillCircle(buf, Math.round(x0 + (x1 - x0) * t), Math.round(y0 + (y1 - y0) * t), Math.floor(w / 2), color);
  }
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------
function textWidth(text, scale) {
  if (!text || text.length === 0) return 0;
  return text.length * ADVANCE * scale - scale; // no trailing spacing
}

// Draw left-aligned text at (x, y) top-left. Returns width drawn.
function drawText(buf, text, x, y, scale, color) {
  const s = Math.max(1, Math.floor(scale));
  let cx = Math.round(x);
  const cy = Math.round(y);
  for (const ch of text) {
    const glyph = FONT[ch] || FONT[' '];
    for (let row = 0; row < GLYPH_H; row++) {
      const line = glyph[row];
      for (let col = 0; col < GLYPH_W; col++) {
        if (line[col] === '#') {
          fillRect(buf, cx + col * s, cy + row * s, s, s, color);
        }
      }
    }
    cx += ADVANCE * s;
  }
  return cx - Math.round(x) - s;
}

function drawCenteredText(buf, text, centerX, y, scale, color) {
  const w = textWidth(text, scale);
  drawText(buf, text, centerX - w / 2, y, scale, color);
}

// Shrink scale until the text fits maxWidth. Never below 1.
function fitScale(text, maxScale, maxWidth) {
  let s = Math.max(1, Math.floor(maxScale));
  while (s > 1 && textWidth(text, s) > maxWidth) s -= 1;
  return s;
}

// Normalize free-form input so it always renders as visible glyphs:
// fold accented Latin to ASCII (NFD strip), map common punctuation to the
// bitmap font, drop anything else later as a space in drawText. Deterministic.
const PUNCT_MAP = {
  '\u2013': '-', '\u2014': '-', '\u2018': "'", '\u2019': "'",
  '\u201C': '"', '\u201D': '"', '\u00AB': '<<', '\u00BB': '>>',
  '\u2026': '...',
};
function printable(text) {
  let t = String(text).normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  for (const [from, to] of Object.entries(PUNCT_MAP)) t = t.split(from).join(to);
  return t;
}

// Split text into at most two lines that each fit maxWidth at scale 1.
// A single word longer than the line is hard-truncated with '...'.
function wrapTwo(text, maxWidth) {
  const t = String(text);
  if (textWidth(t, 1) <= maxWidth) return [t];
  const maxChars = Math.max(1, Math.floor((maxWidth + 1) / ADVANCE));
  const cut = (w) => (w.length > maxChars ? w.slice(0, Math.max(0, maxChars - 3)) + '...' : w);
  const lines = [''];
  for (const raw of t.split(' ')) {
    const word = cut(raw);
    const cur = lines[lines.length - 1];
    const cand = cur ? cur + ' ' + word : word;
    if (textWidth(cand, 1) <= maxWidth) {
      lines[lines.length - 1] = cand;
    } else if (lines.length < 2) {
      lines.push(word);
    } else {
      lines[1] = cut(lines[1] + ' ' + word);
    }
  }
  return lines.map(cut);
}

// Draw a centered name block: one line normally, two wrapped lines when the
// text cannot fit at scale 1. Never overflows maxWidth. Returns extra height
// beyond a single line at the chosen scale (0 for the normal case).
function drawNameBlock(buf, text, centerX, y, maxScale, maxWidth, color) {
  const lines = wrapTwo(text, maxWidth);
  const longest = lines.reduce((a, b) => (textWidth(b, 1) > textWidth(a, 1) ? b : a), '');
  const s = fitScale(longest, maxScale, maxWidth);
  const gap = Math.max(6, Math.floor((GLYPH_H * s) / 3));
  lines.forEach((line, i) => {
    drawCenteredText(buf, line, centerX, y + i * (GLYPH_H * s + gap), s, color);
  });
  const total = lines.length * GLYPH_H * s + (lines.length - 1) * gap;
  return total - GLYPH_H * s;
}

// ---------------------------------------------------------------------------
// PNG encoding
// ---------------------------------------------------------------------------
const crcTable = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    c = crcTable[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function chunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function encodePng(buf) {
  // RGBA canvas -> RGB scanlines with filter byte 0.
  const rowBytes = W * 3 + 1;
  const raw = Buffer.alloc(H * rowBytes);
  for (let y = 0; y < H; y++) {
    const out = y * rowBytes;
    raw[out] = 0; // filter: none
    for (let x = 0; x < W; x++) {
      const src = (y * W + x) * 4;
      const dst = out + 1 + x * 3;
      raw[dst] = buf[src];
      raw[dst + 1] = buf[src + 1];
      raw[dst + 2] = buf[src + 2];
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0);
  ihdr.writeUInt32BE(H, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 2;   // color type: RGB
  ihdr[10] = 0;  // compression
  ihdr[11] = 0;  // filter
  ihdr[12] = 0;  // interlace
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ---------------------------------------------------------------------------
// Certificate layout
// ---------------------------------------------------------------------------
function renderCertificate({ pathName, studentName, dateStr, installFingerprint, verifyCode, pathId }) {
  const buf = newCanvas();

  const name = printable(pathName == null ? '' : pathName);
  const student = printable(studentName == null ? '' : studentName);
  const date = printable(dateStr == null ? '' : dateStr);
  const fingerprint = printable(installFingerprint == null ? '' : installFingerprint);
  const code = printable(verifyCode == null ? '' : verifyCode);
  const pid = printable(pathId == null ? '' : pathId);

  // Decorative orbs (behind everything else).
  fillCircle(buf, 150, 150, 78, C.orbPink);
  fillCircle(buf, 1052, 138, 92, C.orbLight);
  fillCircle(buf, 168, 706, 62, C.orbLight);
  fillCircle(buf, 1040, 700, 74, C.orbPink);
  fillCircle(buf, 985, 220, 16, C.pink);
  fillCircle(buf, 205, 250, 12, C.violet);
  fillCircle(buf, 230, 620, 10, C.pink);

  // Double border: thick violet rounded rect + thin inner line.
  outlineRoundedRect(buf, 20, 20, W - 40, H - 40, 26, 12, C.deepViolet, C.bg);
  outlineRoundedRect(buf, 48, 48, W - 96, H - 96, 16, 3, C.violet, C.bg);

  const CX = W / 2;

  // Header brand line.
  drawCenteredText(buf, 'PenTrix VulnLab', CX, 96, 3, C.violet);
  // Small pink bar under the header.
  fillRoundedRect(buf, CX - 60, 96 + GLYPH_H * 3 + 12, 120, 8, 4, C.pink);

  // Title.
  drawCenteredText(buf, 'Certificate of Completion', CX, 178, 5, C.ink);
  // Violet divider bar under the title.
  fillRoundedRect(buf, CX - 90, 178 + GLYPH_H * 5 + 16, 180, 10, 5, C.violet);

  // Path name, auto-fit to the inner width; wraps to two lines when it
  // cannot fit even at scale 1. Later blocks shift down by the extra height.
  const pathExtra = drawNameBlock(buf, name, CX, 300, 6, 960, C.deepViolet);

  // Awarded to + student name.
  drawCenteredText(buf, 'Awarded to', CX, 442 + pathExtra, 3, C.muted);
  const studentExtra = drawNameBlock(buf, student, CX, 486 + pathExtra, 5, 960, C.ink);

  // Completed date.
  drawCenteredText(buf, 'Completed ' + date, CX, 606 + pathExtra + studentExtra, 3, C.muted);

  // Divider above the footer block.
  fillRoundedRect(buf, CX - 300, 678, 600, 4, 2, C.orbLight);

  // Seal position (drawn after the footer): bottom right inside the border.
  const sx = 1062;
  const sy = 744;

  // Footer: left-aligned details. Every line is fit to stay clear of the seal
  // (seal left edge sx-54, minus a 12px gap).
  const fx = 130;
  const footerMaxW = (sx - 66) - fx;
  const installLine = 'Install ' + fingerprint;
  drawText(buf, installLine, fx, 706, fitScale(installLine, 2, footerMaxW), C.muted);
  const codeLine = 'Verification code ' + code;
  drawText(buf, codeLine, fx, 736, fitScale(codeLine, 2, footerMaxW), C.muted);
  // "Verify at " in muted, URL in violet.
  const prefix = 'Verify at ';
  const url = '/paths/' + pid + '/verify?code=' + code;
  const urlMaxWidth = footerMaxW;
  const urlScale = fitScale(prefix + url, 2, urlMaxWidth);
  drawText(buf, prefix, fx, 766, urlScale, C.muted);
  drawText(buf, url, fx + textWidth(prefix, urlScale) + urlScale, 766, urlScale, C.violet);

  // Seal: violet ring, pink center, white check. Bottom right inside border.
  fillCircle(buf, sx, sy, 54, C.violet);
  fillCircle(buf, sx, sy, 44, C.pink);
  thickLine(buf, sx - 20, sy + 1, sx - 6, sy + 15, 11, C.white);
  thickLine(buf, sx - 6, sy + 15, sx + 22, sy - 17, 11, C.white);

  return encodePng(buf);
}

module.exports = { renderCertificate, W, H };
