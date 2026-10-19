# DESIGN BRIEF: PenTrix VulnLab visual transformation

Date: 2026-10-19, revised same day per owner direction (see D15).
Role: design researcher. All audit findings were observed directly: curl on
http://localhost:3000, full reads of public/style.css (83 lines) and
lib/page.js (41 lines). No files were changed during the audit.

Visual direction: **High-Fidelity Claymorphism** ("digital clay"), chosen by
the owner 2026-10-19, replacing the earlier "Precision Instrument" direction.
Component inspiration: https://uiverse.io (open-source CSS UI elements),
hand-ported to vanilla CSS (see section 9).

Constraints this brief designs within:

- Server-rendered Express, no view engine, template strings in lib/page.js,
  no client-side JS framework, no build step, no Tailwind, no new npm
  dependencies. Every Tailwind-ism in the clay reference (rounded-[32px],
  shadow-clayCard, bg-gradient-to-br) is translated to vanilla CSS custom
  properties and plain classes in this brief. Design proposals must be
  expressible as CSS plus small progressive-enhancement scripts.
- Light-only theme. Clay is inherently a light aesthetic (pale canvas,
  soft shadows need light to read); the owner prefers light themes.
- Explicitly banned visual language: neon-green-on-black hacker cliche,
  generic admin templates, excessive gradients and glow, sharp corners.
- No em dashes in any file (style rule).

---

## 1. Current UI audit

### 1.1 Information architecture (observed)

Three top-level routes, one shared template:

- `/` (Modules): hero block (title, one paragraph, two buttons) plus a grid
  of 29 module cards. Each card: name, one-line tagline, difficulty pill,
  flag count (`0/11 flags`). No grouping, no search, no sorting. Cards are
  ordered alphabetically by module id, not by pedagogical path.
- `/scoreboard`: overall progress (`0 / 235 flags captured` plus a bar),
  then one dense table per module: checkbox glyph, vuln name, difficulty,
  status. 235 rows on one page. 31,224 bytes of HTML.
- `/about`: warnings, how-to-use steps, lab rules.
- `/:module`: module briefing (`.brief`) plus a list of challenge cards
  (`.vuln-card`, a class NOT defined in style.css, so it renders unstyled)
  or raw `<table>` markup with no `.tbl` class (cmdi observed).
- `/:module/:challenge`: raw per-module markup. Observed on sqli/login:
  bare `<form>` with `<label>Username: <input/></label><br/>` pattern and an
  unstyled submit button. Observed on cmdi/ping: unclassed form, same pattern.

Layout skeleton is consistent (topbar, main.wrap max-width 1080px, footer),
but per-module content varies because helpers beyond page/esc/flagBox/
hintBox/brief are ad hoc.

### 1.2 Typography (observed)

- Body: system-ui stack, 16px, line-height 1.6. Reasonable but generic.
- Headings: default weights, hero h1 at 2.2em with tight letter-spacing.
- Code: ui-monospace stack, panel background chips. Good choice, keep.
- No type scale discipline: h1/h2/h3 sizes are browser defaults outside the
  hero. No font loading, no webfonts.

### 1.3 Spacing and layout (observed)

- Wrap: max-width 1080px, 32px top padding. Card gap 16px, card padding 20px.
- The scale works but is accidental: only a handful of values are reused.
- `.grid` min card width 280px, auto-fill. Fine on desktop, collapses to one
  column on mobile, acceptable.
- `.tbl` has border-radius with overflow hidden, a nice touch, but modules
  that emit plain `<table>` (cmdi) miss it entirely: no borders, no padding.

### 1.4 States (observed)

- Loading: none exists and none is needed for server-rendered pages. Any
  future client-side additions must add a loading state explicitly.
- Empty: scoreboard always shows every row, even at 0 flags. There is no
  "you have not captured anything yet, here is where to start" empty state.
- Success: `.flagbox` (green tinted box with the flag in `<code>`). Works,
  but appears only as plain page content on reload after capture.
- Error: Express default 404 (`Cannot GET /nope`) is unstyled, no navigation,
  no search, dead end. Challenge errors render raw query text in `.warn` or
  `pre.out` with no consistent pattern.
- Form errors: none observed (no validation styling at all).
- No focus styles anywhere: keyboard users get no visible focus indicator.
  This is the single largest accessibility gap.

### 1.5 Accessibility gaps (observed)

1. No `:focus-visible` styling (browsers show only the faint default outline,
   and it is suppressed nowhere, so it survives, but it looks broken).
2. Status is conveyed by emoji/checkbox glyphs only (⬜ / 🚩 / ✅). Screen
   readers hear the emoji; add visually-hidden text labels.
3. Difficulty is a text pill already (good), but color is not part of the
   system, so no mapping exists to build on.
4. Color contrast: `--dim #8b93a7` on `--bg #0b0e14` is roughly 5.5:1,
   passes AA for body text, but the palette is not documented so modules
   cannot rely on it.
5. Tables lack `<th scope>` and captions. Scoreboard tables have no heading
   association for assistive tech (the `<h3 class="modhead">` above each
   table is visual only; use `aria-labelledby`).
6. `<details>` hint boxes are natively keyboard accessible (good, keep).
7. No `prefers-reduced-motion` handling anywhere (currently moot: there is
   almost no motion; only the `.modcard:hover` lift and `.bar` width
   transition exist).
8. The decorative emoji in the brand (`🧪`) is announced by screen readers;
   mark it `aria-hidden` and add a text label.

### 1.6 Strengths to keep

- One tiny stylesheet and four template helpers keep 29 modules visually
  coherent with zero build. The architecture is correct for the product;
  the problem is thinness, not wrongness.
- Native `<details>` for hints is the right call.
- Monospace treatment of payloads and flags reads well.

---

## 2. User journeys (design targets)

### J1. Discover a lab
Arrive at `/` -> scan modules -> pick a starting point. Design must answer,
in under 10 seconds: where do beginners start, what did I already do, what
is next. Requires: difficulty ordering or filter, per-module progress on the
card, a "start here" affordance.

### J2. Launch a challenge
Module page -> read briefing -> choose challenge. Design must make the
briefing scannable (what to attack, example payloads as copyable blocks)
and the challenge list scannable (difficulty, status, estimated approach).

### J3. Exploit
Challenge page -> form/gadget interaction -> output in `pre.out` or inline
results. Design must: keep forms and output visually connected, distinguish
attacker input from server output, make payloads copyable, keep focus
management sane after form submission (focus returns to input or output).
Clay playfulness is dialed down here: challenge pages stay clear and
readable; tactile feedback lives in buttons and inputs, not in decoration.

### J4. Capture flag
Flag appears -> celebration -> recorded on scoreboard. Design must: make the
capture moment unmistakable (this is the product's core reward loop),
confirm persistence ("saved to your scoreboard"), offer a next step
(next challenge, back to module, scoreboard). The capture banner is the one
place where clay exuberance is fully welcome (squish, pop, emerald).

### J5. Track progress
Scoreboard -> see totals, per-module completion, find unfinished work.
Design must: support scanning 235 rows (grouping, sticky headers, filter by
status), make captured vs not-captured obvious without color alone.

---

## 3. Visual direction: High-Fidelity Claymorphism

### 3.1 Brand feel

Digital clay: every element feels like a premium matte vinyl toy, soft
silicone, dense and touchable. The world is lit by a soft diffused overhead
light from the top-left; objects bulge toward the viewer, cast soft colored
shadows, and squish when pressed. Playful and optimistic (candy-store
palette, bouncy organic motion), tactile and responsive (everything
physically reacts), friendly and safe (zero sharp corners anywhere).

Three adjectives: tactile, joyful, premium. Memorability comes from the
materiality itself: 4-layer shadow stacks, super-rounded geometry, candy
colors on a pale lavender canvas.

This is a deliberate contrast with the previous "Precision Instrument"
direction (retired per D15): where that direction prized restraint, clay
prizes warmth. The mitigation for a security-training tool is placement:
playfulness lives in the shell (cards, buttons, blobs, capture moment);
challenge pages stay clear, high-contrast, and readable.

### 3.2 Theme strategy: light-only

Ship one light theme. Rationale:

- Clay is inherently light: the 4-layer shadow stacks (ambient occlusion
  below, highlight above) only read on a pale canvas. A dark clay theme
  would be a different design system, not a palette swap.
- The owner prefers light themes across his work.
- Light themes render code, payloads, and tables better for long study
  sessions and report screenshots (students paste screenshots into reports).
- One theme halves the QA surface (no theme-switch layout shifts to test).

No theme toggle, no `data-theme` attribute, no pre-paint script. If a dark
mode is ever requested, it must be designed as its own clay-dark system,
not derived by inverting these tokens.

### 3.3 Color system (CSS custom properties)

Canvas and text:

```css
--clay-canvas: #F4F1FA;   /* page background, pale lavender-white */
--clay-card: #ffffff;     /* solid card surfaces */
--clay-ink: #332F3A;      /* primary text, soft charcoal */
--clay-muted: #635F69;    /* secondary text, darkest allowed gray */
```

Accents (candy palette):

```css
--clay-violet: #7C3AED;   /* primary: CTAs, links, brand emphasis */
--clay-violet-light: #A78BFA; /* gradient partner for buttons */
--clay-pink: #DB2777;     /* secondary emphasis, hard difficulty */
--clay-sky: #0EA5E9;      /* informational, background blobs */
--clay-emerald: #10B981;  /* success, checkmarks, positive indicators */
--clay-amber: #F59E0B;    /* warnings, medium difficulty, ratings */
```

Contrast ratios (computed 2026-10-19, WCAG 2.2):

| Pair | Ratio | Verdict | Allowed use |
|---|---|---|---|
| `--clay-ink` on `--clay-canvas` | 11.69:1 | AAA | body text, headings |
| `--clay-muted` on `--clay-canvas` | 5.58:1 | AA | secondary text, labels |
| `--clay-ink` on `--clay-card` (white) | 13.06:1 | AAA | card text |
| `--clay-muted` on `--clay-card` (white) | 6.23:1 | AA | card secondary text |
| white on `--clay-violet` | 5.70:1 | AA | primary button text |
| `--clay-violet` on white | 5.70:1 | AA | accent text, links on cards |
| `--clay-violet` on `--clay-canvas` | 5.10:1 | AA | accent text on page |
| white on `--clay-pink` | 4.60:1 | AA | secondary button/label text |
| `--clay-pink` on `--clay-canvas` | 4.12:1 | AA large only | large/bold text only, never body |
| white or ink on `--clay-sky` | 2.77 / 2.48:1 | FAIL | never for text; blobs and decorative fills only |
| white or ink on `--clay-emerald` | 2.54 / 2.27:1 | FAIL | never for text; icon orbs and dots only, always paired with a text label |
| white or ink on `--clay-amber` | 2.15 / 1.92:1 | FAIL | never for text; stars, dots, blobs only |

Usage rules derived from the table:

- Body text is always `--clay-ink` or `--clay-muted`. No exceptions; never
  go lighter than `--clay-muted`.
- Sky, emerald, and amber never carry text or standalone meaning. They
  color blobs, icon orbs, dots, and stars, always paired with an adjacent
  text label in ink or muted (the existing icon-plus-text rule).
- Difficulty language (color plus text, never color alone): Easy gets an
  emerald dot, Medium an amber dot, Hard a pink dot, each next to the text
  label "Easy" / "Medium" / "Hard" in ink on a tinted pill.
- Gradient text is reserved for hero-scale display type only (2.5rem and
  up), never for UI labels.

### 3.4 Typography

- Headings: Nunito, weights 700/800/900, tight tracking on display sizes.
  Rounded terminals match the clay geometry.
- Body: DM Sans, weights 400/500/700, relaxed leading.
- Code and payloads: `ui-monospace, "Cascadia Code", "JetBrains Mono",
  Menlo, Consolas, monospace` (unchanged from current; payloads are the
  product's content and the mono treatment is a feature).

Font loading: Google Fonts `<link>` with `display=swap` (one request for
both families). This adds no npm dependency and no build step. Offline
fallback stacks (the lab runs locally and may be offline):

```css
--font-display: "Nunito", ui-rounded, "SF Pro Rounded", system-ui, sans-serif;
--font-body: "DM Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
```

If the webfonts fail, the page falls back to rounded system fonts on Apple
platforms and clean system-ui elsewhere; layout does not depend on the
webfonts (no fixed heights tied to font metrics).

Type scale (rem-based, 1rem = 16px): display 3.5rem/1.1 (hero, Nunito 900,
tight), h1 2.25rem/1.15, h2 1.5rem/1.3, h3 1.15rem/1.4, body 1rem/1.65
(DM Sans 400/500), small 0.875rem/1.5, micro 0.75rem/1.4 (labels, pills,
meta, uppercase tracking-wide). Line length capped at 65ch for prose.

### 3.5 Spacing, radii, elevation

Base unit 4px. Scale: `--s1: 4px, --s2: 8px, --s3: 12px, --s4: 16px,
--s6: 24px, --s8: 32px, --s12: 48px, --s16: 64px`. Section rhythm: 48px
between sections, 24px between blocks, 12px between related items.

Radii (absolute px values per the clay spec; the super-rounded rule):

```css
--r-hero: 48px;   /* large containers, hero panels (up to 60px) */
--r-card: 32px;   /* standard cards, the default */
--r-med: 24px;    /* benefit pills, blog-style cards, inner images */
--r-btn: 20px;    /* buttons and inputs (rounded-2xl equivalent) */
--r-icon: 16px;   /* square icon containers */
--r-pill: 999px;  /* pills, badges, stat orbs, progress tracks */
```

Rules: never below 20px on any visible container; nested radii step down
by 8px (a 32px card holds a 24px inner panel); minimum 44px touch targets
are unaffected by radii.

Elevation is the 4-layer shadow stacks (section 3.6), not flat drop
shadows. Borders are rare in clay (shadows do the separation work); where
a hairline is needed: 1px `rgba(51,47,58,.08)`.

### 3.6 Shadow stacks (copy-pasteable CSS)

The engine of the aesthetic. Every stack simulates one overhead
top-left light: ambient occlusion below, highlight above, inner bounce
light. Defined once as custom properties, reused everywhere.

```css
:root {
  /* 1. Deep clay: large containers, hero panels */
  --shadow-clay-surface:
    30px 30px 60px #cdc6d9,
    -30px -30px 60px #ffffff,
    inset 10px 10px 20px rgba(139, 92, 246, 0.05),
    inset -10px -10px 20px rgba(255, 255, 255, 0.8);

  /* 2. Clay card: standard floating cards */
  --shadow-clay-card:
    16px 16px 32px rgba(160, 150, 180, 0.2),
    -10px -10px 24px rgba(255, 255, 255, 0.9),
    inset 6px 6px 12px rgba(139, 92, 246, 0.03),
    inset -6px -6px 12px rgba(255, 255, 255, 1);

  /* 3. Clay button: high convexity, clickable elements */
  --shadow-clay-button:
    12px 12px 24px rgba(139, 92, 246, 0.3),
    -8px -8px 16px rgba(255, 255, 255, 0.4),
    inset 4px 4px 8px rgba(255, 255, 255, 0.4),
    inset -4px -4px 8px rgba(0, 0, 0, 0.1);

  /* 4. Clay pressed: recessed inputs and active states */
  --shadow-clay-pressed:
    inset 10px 10px 20px #d9d4e3,
    inset -10px -10px 20px #ffffff;
}
```

The clay physics, in one paragraph for implementers: convex elements
(buttons, cards, orbs) bulge toward the viewer with the card/button
stacks; concave elements (inputs, pressed buttons, open panels) sink
with the pressed stack; hover lifts an element (translateY up plus a
deeper shadow); active press squishes it (scale down plus the pressed
stack). Never mix convex and concave stacks on one element.

### 3.7 Background blobs

Never a flat background. Every page gets 3 to 4 large drifting blobs
behind the content:

```css
.blobs {
  position: fixed; inset: 0; overflow: hidden;
  z-index: -1; pointer-events: none;
}
.blob {
  position: absolute; width: 60vh; height: 60vh;
  border-radius: 50%; filter: blur(80px);
}
.blob-1 { background: rgba(139, 92, 246, .10); top: -10%; left: -10%; }
.blob-2 { background: rgba(219, 39, 119, .10); top: 20%; right: -10%; }
.blob-3 { background: rgba(14, 165, 233, .10); bottom: -15%; left: 25%; }
```

Blobs drift on 8 to 12s keyframe loops (see MOTION_SYSTEM.md) and freeze
under `prefers-reduced-motion`. Because the palette fails text contrast
on sky/emerald/amber, blobs are strictly decorative: `aria-hidden`,
`pointer-events: none`, never behind small text without a card surface
between them and the copy.

### 3.8 Signature elements (what makes it memorable)

1. The flag-capture moment: a clay celebration banner (emerald orb,
   squish-and-pop, see 4.5). One exuberant component, used in exactly
   one place.
2. Clay module cards: numbered specimen orbs, tagline, difficulty pill,
   progress; they lift on hover and squish on press.
3. Monospace everything-attackable: payloads, flags, and outputs share
   one recessed well treatment so the eye learns "mono = do something
   with this".

---

## 4. Component specs (vanilla CSS)

Naming: `.clay-*` classes in the single stylesheet. No Tailwind, no
framework; each spec below is directly implementable.

### 4.1 Topbar

Sticky clay pill: floating rounded bar (`border-radius: 32px`), card
surface with `--shadow-clay-card`, 16px page margins so it floats over
the blobs. Contents: brand (clay orb logo mark plus wordmark in Nunito
800), nav links, compact progress chip (`n / 235 flags`) as a recessed
pill. `aria-current="page"` on the active link, `aria-hidden` on the
decorative emoji. Height 64px desktop, 56px mobile.

### 4.2 Module card (home grid)

```css
.clay-card {
  position: relative; overflow: hidden;
  border-radius: var(--r-card);           /* 32px */
  background: rgba(255, 255, 255, .72);   /* glass-clay hybrid */
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  padding: 32px; color: var(--clay-ink);
  box-shadow: var(--shadow-clay-card);
  transition: transform .5s cubic-bezier(.22,1,.36,1),
              box-shadow .5s cubic-bezier(.22,1,.36,1);
}
a.clay-card:hover {
  transform: translateY(-8px);
  box-shadow: 24px 24px 48px rgba(160,150,180,.28),
    -12px -12px 28px rgba(255,255,255,.95),
    inset 6px 6px 12px rgba(139,92,246,.04),
    inset -6px -6px 12px rgba(255,255,255,1);
}
```

Structure: header row (numbered orb `01` plus difficulty pill right),
title (Nunito 800), tagline (DM Sans, muted), footer strip (mini progress
track plus `3/11 flags`). Focus-visible: 4px violet ring offset 3px.
Card is a single link; progress text is plain text inside, no nested
interactive elements. Bento rhythm on the home grid: mix standard cards
with one wide hero card per row; never a uniform wall.

### 4.3 Clay button

```css
.clay-btn {
  display: inline-flex; align-items: center; justify-content: center;
  min-height: 56px; padding: 0 28px;
  border: 0; border-radius: var(--r-btn);  /* 20px */
  font: 700 1rem/1 var(--font-body); letter-spacing: .02em;
  cursor: pointer;
  transition: transform .2s cubic-bezier(.22,1,.36,1),
              box-shadow .2s cubic-bezier(.22,1,.36,1);
}
.clay-btn-primary {
  color: #fff;
  background: linear-gradient(135deg, var(--clay-violet-light), var(--clay-violet));
  box-shadow: var(--shadow-clay-button);
}
.clay-btn-primary:hover { transform: translateY(-4px); }
.clay-btn-primary:active {
  transform: scale(.92);                  /* the squish */
  box-shadow: var(--shadow-clay-pressed);
}
.clay-btn-secondary {
  color: var(--clay-ink); background: #fff;
  box-shadow: var(--shadow-clay-button);
}
.clay-btn:focus-visible {
  outline: none;
  box-shadow: var(--shadow-clay-button),
    0 0 0 4px rgba(124, 58, 237, .30);
}
```

Variants: primary (violet gradient, white text, 5.70:1), secondary
(white, ink text), outline (2px violet border at 20% alpha, transparent
fill), ghost (text button). Sizes: sm 44px, default 56px, lg 64px;
full-width on mobile for primary CTAs.

### 4.4 Recessed input

```css
.clay-input {
  width: 100%; min-height: 56px;
  border: 0; border-radius: 16px;
  background: #EFEBF5; color: var(--clay-ink);
  padding: 16px 24px; font: 500 1.0625rem/1.4 var(--font-body);
  box-shadow: var(--shadow-clay-pressed);
  transition: background-color .2s, box-shadow .2s;
}
.clay-input::placeholder { color: var(--clay-muted); }
.clay-input:focus {
  outline: none; background: #fff;
  box-shadow: var(--shadow-clay-card),
    0 0 0 4px rgba(124, 58, 237, .20);
}
```

One form pattern replaces the ad-hoc `<br/>` label forms: stacked field
groups (label above input, 8px gap), visible focus ring, error text in
`#b3261e` (6.10:1 on canvas, computed) with `aria-describedby`. Never
style `button` globally without a class.

### 4.5 Flag capture banner

Replaces the plain `.flagbox`. Anatomy: emerald icon orb (decorative;
the "Captured" text beside it carries the meaning), "Flag captured"
heading in Nunito 800, the flag in a recessed mono well with a copy
button, a "saved to your scoreboard" confirmation line, and next-step
clay buttons (next challenge, module page, scoreboard). Motion: one
squish-and-pop on appearance (see MOTION_SYSTEM.md). Reachable by
keyboard, announced via `role="status"`.

### 4.6 Hint disclosure

Keep native `<details>/<summary>`. Style: white clay card at small radius
(20px), summary row with an amber dot plus "Hint" label and a chevron that
rotates on open. Add a "used hint" state (subtle, non-punitive) so
students can track which challenges they solved with help.

### 4.7 Briefing panel

Clay card with a violet orb number and a "Mission brief" eyebrow label in
micro caps. Scannable paragraphs; example payloads promoted from inline
prose to recessed mono wells with copy buttons.

### 4.8 Challenge list

One pattern for all modules (replacing the current mix of unstyled
`.vuln-card` divs and raw tables): clay list rows, 20px radius, each with
challenge name (link), difficulty pill (dot plus text), status (emerald
orb plus "Captured" text, or muted "Not captured"), and the hint
`<details>` inline. Tables are reserved for the scoreboard only.

### 4.9 Scoreboard

Clay cards per module instead of one endless table page: module header
(orb, name, per-module progress bar), rows with icon-plus-text status,
sticky section headers, `<caption>` and `aria-labelledby` where tables
remain, `<th scope="col">`. Client-side filter (status, text search) as
progressive enhancement with the full list as the no-JS fallback. Starter
panel at 0 flags ("No flags yet. Begin with..." linking the easiest
first challenge).

### 4.10 Terminal output (`pre.out`)

Recessed well treatment: header strip ("Output" plus copy button) above
a `#F4F1FA`-darkened mono body with `--shadow-clay-pressed`. Where
attacker input and server output share a page, label them ("You sent" /
"Server returned").

### 4.11 Pills and progress

Pills: 0.875rem, 700 weight, `--r-pill`, tinted clay backgrounds with
ink text (tints at 12% alpha over white keep ink contrast AAA). Progress:
recessed track (`--shadow-clay-pressed`, 12px height, pill radius),
violet gradient fill, percentage text alongside (never bar alone).

### 4.12 404 and error pages

Style the 404 in the page template (it currently bypasses page.js): a
small clay card explaining what happened, where to go (modules,
scoreboard), the lab's "run locally" reminder. Same for 500: generic
message, no stack trace leakage (security relevance: verbose errors are
literally a module topic).

### 4.13 Empty states

Scoreboard at 0 flags: starter panel above the data. Module at 100%: a
completion note with next-module suggestion, both as clay cards with
emerald orbs.

---

## 5. Accessibility acceptance criteria

- Every interactive element shows a visible `:focus-visible` ring
  (4px violet at 30% alpha, 3px offset, clay-compatible).
- All status conveyed by icon also has text (Captured / Not captured).
- Contrast: the pairs table in 3.3 is the law. Body text minimum AA
  (4.5:1); sky/emerald/amber never carry text or standalone meaning.
- Keyboard: full task completion without a mouse (discover, exploit via
  forms, capture, navigate). Hint disclosures are native and keep working.
- Screen readers: landmarks (header/main/footer already present),
  table captions and scopes, `aria-current` on nav, `role="status"` on
  the flag banner, `aria-hidden` on decorative emoji and blobs.
- `prefers-reduced-motion`: all motion disabled, blobs frozen, state
  changes instant (details in MOTION_SYSTEM.md).
- Touch: 44px minimum targets, tables scroll horizontally in a wrapper
  rather than breaking layout.

## 6. Performance acceptance criteria

- No render-blocking JS added to the critical path; enhancement scripts
  load with `defer` and are optional (page works without them).
- CSS budget: keep the single stylesheet under ~25 KB unminified (shadow
  stacks and component variants cost more than the old 83-line file; the
  budget is honest about that, still tiny).
- Backdrop blur is used sparingly (cards only, never on full-page
  surfaces); blob blur is a static filter, and blob animation touches
  transform only.
- No layout shift on enhancement load (reserve space, do not inject above
  content). No theme switch exists to shift.
- Motion restricted to transform and opacity (see MOTION_SYSTEM.md).

## 7. Implementation notes for the build phase

- The design is implementable as: expanded `public/style.css` (tokens in
  `:root`, the four shadow stacks, components), extended helpers in
  `lib/page.js` (new helpers for pills, progress, empty states, copy
  buttons, blobs container), Google Fonts `<link>` in the page head, and
  one small `public/app.js` (defer) for copy buttons, scoreboard filter,
  and reveal animations. No framework, no build step preserved.
- Per-module router markup should migrate to the shared helpers over time;
  the `.vuln-card` class (currently undefined) and raw `<table>` markup
  are the two inconsistencies to normalize first.
- Do not add Tailwind, React, or a component library: uiverse.io and
  Aceternity UI are inspiration sources whose CSS is hand-ported (see
  section 9), never vendored.

## 8. uiverse.io: how to use it as inspiration

https://uiverse.io is an open-source library of CSS UI elements
(buttons, cards, inputs, loaders, toggles) built by the community. The
owner named it as component inspiration alongside the clay system. Rules
for using it in this project:

1. Browse by element type when a component needs a fresh treatment
   (a better copy button, a toggle, a loader). Study the technique, not
   the code: what makes the hover feel good, how the shadow layers are
   ordered, how the active state compresses.
2. Hand-port the CSS by hand into the clay token system. Translate every
   color to a `--clay-*` variable, every radius to the `--r-*` scale,
   every shadow to one of the four stacks (or a documented deliberate
   variant). Never paste a uiverse snippet wholesale: pasted code brings
   its own palette, its own radii, and often Tailwind classes this
   project cannot use.
3. Never paste Tailwind classes. The project has no Tailwind and no
   build step; a `class="rounded-[32px] shadow-lg"` paste is dead code
   here. Port the visual idea to plain CSS.
4. Keep `public/style.css` tokens as the single source of truth. If a
   ported element needs a token that does not exist, add the token to
   `:root` with a comment naming its purpose; do not hardcode hex values
   in component rules.
5. Check contrast before adopting anything decorative-turned-meaningful:
   run new color pairs through the ratio check in 3.3. Community CSS is
   not accessibility-reviewed.
6. Credit nothing in the UI; uiverse elements are MIT-licensed community
   contributions and the ported result is transformed, but keep a comment
   in the CSS noting the inspiration source per element where the debt
   is direct (e.g. `/* toggle technique adapted from uiverse.io */`).

What uiverse.io is NOT for this project: a dependency, a design system
replacement, or a shortcut around the clay tokens. It is a sketchbook.

## 9. Current UI reference renders

Rendered 2026-10-19 from the live local instance (http://localhost:3000)
with docs/qa/screenshot.sh (curl page HTML, inline linked CSS, WeasyPrint
to PDF, pdftoppm first page at 60 dpi). These are the visual baseline the
redesign will be measured against.

- Home (module grid): ../qa/shots/current-home.png
  29 cards, hero block, difficulty pills, per-card flag counters, no
  grouping or search.
- Scoreboard: ../qa/shots/current-scoreboard.png
  Overall progress bar plus one dense table per module (235 rows on one
  page), status shown as checkbox glyph plus "not captured" text.
- Module page (sqli): ../qa/shots/current-module-sqli.png
  Briefing panel plus challenge list with difficulty labels and hints.
- Challenge page (sqli/login): ../qa/shots/current-challenge-sqli-login.png
  Briefing box and the bare unstyled login form; compare with the form
  pattern proposed in section 4.4.

## Sources consulted (research phase)

- High-Fidelity Claymorphism design system spec (owner-provided, 2026-10-19):
  candy palette, Nunito plus DM Sans, super-rounded radii, 4-layer shadow
  stacks, clay Card/Button/Input/blob components, 9-animation system.
- uiverse.io (owner-named inspiration): https://uiverse.io (open-source CSS
  UI elements; browse and hand-port, never vendor).
- GSAP 3.13 release notes and licensing: https://webdevpuneet.com/blog/gsap-tutorial-for-beginners-animate-your-first-html-element/ (all plugins free since April 2025, Webflow acquisition); https://gsap.com/scroll/ (ScrollTrigger docs); https://artofstyleframe.com/blog/gsap-2026-free-license-whats-new/
- Motion (formerly Framer Motion), current state: https://github.com/motiondivision/motion ; https://Refine.dev/blog/framer-motion/ (Motion v12, `motion/react` import path)
- Lenis smooth scroll: https://dev.to/keymelgaston/i-went-looking-for-why-lenis-beat-locomotive-scroll-the-real-story-surprised-me-4ed3 ; https://socket.dev/npm/package/@studio-freight/lenis/overview/1.0.12
- Aceternity UI: https://ui.aceternity.com/blocks/navbars/navbar-classic ; https://www.pulsetools.site/posts/aceternity-ui-review-2026.html
- Contrast ratios in 3.3 computed locally 2026-10-19 with the WCAG
  relative-luminance formula; pairs marked FAIL are documented as
  decorative-only, never for text.
