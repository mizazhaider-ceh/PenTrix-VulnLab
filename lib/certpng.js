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
  paper: [253, 250, 243],     // warm ivory certificate paper
  gold: [198, 161, 91],       // certificate gold
  goldLight: [226, 205, 160], // light gold
  guilloche: [199, 190, 230], // fine security-pattern violet
  sealLight: [167, 150, 226], // wax seal inner
  emboss: [228, 220, 208],    // name emboss shadow on paper
  hairline: [219, 210, 192],  // footer rules
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
  const s = Math.max(1, Math.floor(scale));
  let w = 0;
  for (const ch of text) w += glyphAdvance(ch);
  return w * s - s; // no trailing spacing
}

// Proportional advance: ink width plus 1px tracking, so narrow letters
// (i, l, r, t, f) do not leave wide gaps that fragment words. Spaces and
// missing glyphs keep the full cell advance.
function glyphAdvance(ch) {
  if (ch === ' ') return ADVANCE;
  const glyph = FONT[ch];
  if (!glyph) return ADVANCE;
  let minCol = GLYPH_W, maxCol = -1;
  for (let row = 0; row < GLYPH_H; row++) {
    const line = glyph[row];
    for (let col = 0; col < GLYPH_W; col++) {
      if (line[col] === '#') {
        if (col < minCol) minCol = col;
        if (col > maxCol) maxCol = col;
      }
    }
  }
  if (maxCol < 0) return ADVANCE;
  const inkW = maxCol - minCol + 1;
  return Math.min(ADVANCE, Math.max(3, inkW + 1));
}

// Draw left-aligned text at (x, y) top-left. Returns width drawn.
function drawText(buf, text, x, y, scale, color) {
  const s = Math.max(1, Math.floor(scale));
  let cx = Math.round(x);
  const cy = Math.round(y);
  for (const ch of text) {
    const glyph = FONT[ch] || FONT[' '];
    // Shift ink left so it starts at the glyph origin (drops the font's
    // built-in left bearing); the proportional advance supplies spacing.
    let minCol = GLYPH_W;
    for (let row = 0; row < GLYPH_H; row++) {
      const line = glyph[row];
      for (let col = 0; col < GLYPH_W; col++) {
        if (line[col] === '#') { if (col < minCol) minCol = col; break; }
      }
      if (minCol === 0) break;
    }
    if (minCol === GLYPH_W) minCol = 0;
    for (let row = 0; row < GLYPH_H; row++) {
      const line = glyph[row];
      for (let col = 0; col < GLYPH_W; col++) {
        if (line[col] === '#') {
          fillRect(buf, cx + (col - minCol) * s, cy + row * s, s, s, color);
        }
      }
    }
    cx += glyphAdvance(ch) * s;
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

// Filled diamond (rotated square) centered at (cx, cy) with radius r.
function fillDiamond(buf, cx, cy, r, color) {
  const x0 = Math.round(cx), y0 = Math.round(cy), rr = Math.round(r);
  for (let y = -rr; y <= rr; y++) {
    const w = rr - Math.abs(y);
    for (let x = -w; x <= w; x++) setPixel(buf, x0 + x, y0 + y, color);
  }
}

// Tracked (letter-spaced) text: like drawText with extra tracking unit px
// between glyphs. Used for small-caps labels.
function trackedWidth(text, scale, tracking) {
  const s = Math.max(1, Math.floor(scale));
  let w = 0;
  for (const ch of text) w += (glyphAdvance(ch) + tracking) * s;
  return w - tracking * s;
}
function drawTrackedText(buf, text, x, y, scale, color, tracking) {
  const s = Math.max(1, Math.floor(scale));
  let cx = Math.round(x);
  const cy = Math.round(y);
  for (const ch of text) {
    const glyph = FONT[ch] || FONT[' '];
    let minCol = GLYPH_W;
    for (let row = 0; row < GLYPH_H; row++) {
      const line = glyph[row];
      for (let col = 0; col < GLYPH_W; col++) {
        if (line[col] === '#') { if (col < minCol) minCol = col; break; }
      }
      if (minCol === 0) break;
    }
    if (minCol === GLYPH_W) minCol = 0;
    for (let row = 0; row < GLYPH_H; row++) {
      const line = glyph[row];
      for (let col = 0; col < GLYPH_W; col++) {
        if (line[col] === '#') {
          fillRect(buf, cx + (col - minCol) * s, cy + row * s, s, s, color);
        }
      }
    }
    cx += (glyphAdvance(ch) + tracking) * s;
  }
}
function drawCenteredTrackedText(buf, text, centerX, y, scale, color, tracking) {
  const w = trackedWidth(text, scale, tracking);
  drawTrackedText(buf, text, centerX - w / 2, y, scale, color, tracking);
}

// Embossed name block: soft light copy offset down-right, ink on top.
// Same wrapping rules as drawNameBlock. Returns extra height like drawNameBlock.
function drawEmbossedBlock(buf, text, centerX, y, maxScale, maxWidth, color, shadow) {
  const lines = wrapTwo(text, maxWidth);
  const longest = lines.reduce((a, b) => (textWidth(b, 1) > textWidth(a, 1) ? b : a), '');
  const s = fitScale(longest, maxScale, maxWidth);
  const gap = Math.max(6, Math.floor((GLYPH_H * s) / 3));
  const dx = Math.max(2, Math.round(s * 0.8)), dy = Math.max(3, s);
  lines.forEach((line, i) => {
    const ly = y + i * (GLYPH_H * s + gap);
    const w = textWidth(line, s);
    drawText(buf, line, centerX - w / 2 + dx, ly + dy, s, shadow);
    drawText(buf, line, centerX - w / 2, ly, s, color);
  });
  const total = lines.length * GLYPH_H * s + (lines.length - 1) * gap;
  return total - GLYPH_H * s;
}

// Guilloche: three phase-offset sine waves braided into a fine security band.
function drawGuilloche(buf, x0, x1, y, amp, waves, color) {
  const n = Math.max(1, Math.floor(x1 - x0));
  for (let i = 0; i <= n; i++) {
    const x = Math.round(x0) + i;
    for (let p = 0; p < 3; p++) {
      const yy = Math.round(y + amp * Math.sin((i / n) * Math.PI * 2 * waves + p * (Math.PI * 2 / 3)));
      setPixel(buf, x, yy, color);
    }
  }
}

// Scalloped wax-seal disc: lobed edge, for the stamped seal.
function fillScallop(buf, cx, cy, r, lobes, color) {
  const x0 = Math.round(cx), y0 = Math.round(cy), rr = Math.round(r);
  for (let y = -rr; y <= rr; y++) {
    for (let x = -rr; x <= rr; x++) {
      const d = Math.sqrt(x * x + y * y);
      const edge = rr * (0.94 + 0.06 * Math.cos(Math.atan2(y, x) * lobes));
      if (d <= edge) setPixel(buf, x0 + x, y0 + y, color);
    }
  }
}

// Soft radial vignette over the paper: up to 9% darkening at the corners.
function applyVignette(buf) {
  const cx = W / 2, cy = H / 2;
  const maxD = Math.sqrt(cx * cx + cy * cy);
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      const dx = x - cx, dy = y - cy;
      const d = Math.sqrt(dx * dx + dy * dy) / maxD;
      const f = 1 - 0.09 * d * d;
      const i = (y * W + x) * 4;
      buf[i] = Math.round(buf[i] * f);
      buf[i + 1] = Math.round(buf[i + 1] * f);
      buf[i + 2] = Math.round(buf[i + 2] * f);
    }
  }
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

  const CX = W / 2;

  // Ivory paper.
  fillRect(buf, 0, 0, W, H, C.paper);

  // Faint clay orbs behind everything (brand DNA, very low contrast on paper).
  fillCircle(buf, 150, 150, 78, [240, 232, 244]);
  fillCircle(buf, 1052, 138, 92, [238, 230, 242]);
  fillCircle(buf, 168, 706, 62, [240, 232, 244]);
  fillCircle(buf, 1040, 700, 74, [238, 230, 242]);

  // Soft vignette over paper + orbs.
  applyVignette(buf);

  // Guilloche security bands, top and bottom.
  drawGuilloche(buf, 130, 1070, 92, 9, 16, C.guilloche);
  drawGuilloche(buf, 130, 1000, 766, 9, 16, C.guilloche);

  // Double border: thick deep-violet outer, thin gold inner.
  outlineRoundedRect(buf, 24, 24, W - 48, H - 48, 28, 13, C.deepViolet, C.paper);
  outlineRoundedRect(buf, 54, 54, W - 108, H - 108, 18, 3, C.gold, C.paper);
  // Gold diamond ornaments on the inner border corners.
  fillDiamond(buf, 54, 54, 7, C.gold);
  fillDiamond(buf, W - 54, 54, 7, C.gold);
  fillDiamond(buf, 54, H - 54, 7, C.gold);
  fillDiamond(buf, W - 54, H - 54, 7, C.gold);

  // Header brand, letter-spaced small caps.
  drawCenteredTrackedText(buf, 'PENTRIX VULNLAB', CX, 116, 3, C.violet, 2);
  // Gold rule with center diamond under the header.
  fillRect(buf, CX - 150, 162, 140, 3, C.goldLight);
  fillRect(buf, CX + 10, 162, 140, 3, C.goldLight);
  fillDiamond(buf, CX, 163, 7, C.gold);

  // Title.
  drawCenteredText(buf, 'Certificate of Completion', CX, 190, 6, C.ink);

  // Path name: the hero element.
  const pathExtra = drawNameBlock(buf, name, CX, 272, 7, 940, C.deepViolet);

  // Awarded to + embossed student name (the star of the show).
  drawCenteredTrackedText(buf, 'AWARDED TO', CX, 366 + pathExtra, 2, C.muted, 3);
  const studentExtra = drawEmbossedBlock(buf, student, CX, 402 + pathExtra, 8, 940, C.ink, C.emboss);

  // Flourish divider under the name.
  const fy = 402 + pathExtra + studentExtra + GLYPH_H * 8 + 26;
  fillRect(buf, CX - 220, fy, 200, 3, C.goldLight);
  fillRect(buf, CX + 20, fy, 200, 3, C.goldLight);
  fillDiamond(buf, CX, fy + 1, 8, C.gold);

  // Completed date.
  drawCenteredText(buf, 'Completed ' + date, CX, fy + 26, 3, C.muted);

  // Footer: two columns separated by a hairline rule.
  const colA = 330, colB = 800;
  fillRect(buf, 600, 636, 2, 118, C.hairline);
  drawCenteredTrackedText(buf, 'INSTALL', colA, 646, 1, C.muted, 2);
  drawCenteredText(buf, fingerprint, colA, 668, 2, C.ink);
  drawCenteredTrackedText(buf, 'VERIFY AT', colA, 706, 1, C.muted, 2);
  const url = '/paths/' + pid + '/verify?code=' + code;
  drawCenteredText(buf, url, colA, 728, fitScale(url, 2, 400), C.violet);
  drawCenteredTrackedText(buf, 'VERIFICATION CODE', colB, 646, 1, C.muted, 2);
  drawCenteredText(buf, code, colB, 676, fitScale(code, 4, 360), C.deepViolet);

  // Wax seal, stamped bottom-right overlapping the inner border.
  const sx = 1092, sy = 700;
  fillScallop(buf, sx, sy, 66, 18, C.deepViolet);
  fillCircle(buf, sx, sy, 50, C.violet);
  fillCircle(buf, sx, sy, 42, C.sealLight);
  // Highlight arc on the seal.
  for (let a = Math.PI * 1.05; a <= Math.PI * 1.55; a += 0.03) {
    const hx = Math.round(sx + 34 * Math.cos(a)), hy = Math.round(sy + 34 * Math.sin(a));
    fillCircle(buf, hx, hy, 3, [196, 182, 238]);
  }
  // White check.
  thickLine(buf, sx - 20, sy + 1, sx - 6, sy + 15, 12, C.white);
  thickLine(buf, sx - 6, sy + 15, sx + 22, sy - 17, 12, C.white);

  return encodePng(buf);
}

module.exports = { renderCertificate, W, H };
