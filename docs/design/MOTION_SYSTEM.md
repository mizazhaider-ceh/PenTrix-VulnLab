# MOTION SYSTEM: PenTrix VulnLab (claymorphism)

Date: 2026-10-19, revised same day per owner direction (see D15).
Companion to DESIGN_BRIEF.md.
Constraint: server-rendered Express, no build step, no client-side
framework. All motion here is CSS keyframes and transitions plus one
small progressive-enhancement script. No animation libraries. No em
dashes in any file.

---

## 1. Motion principles

1. Two kinds of motion exist: **ambient** (background blobs drift; slow,
   perpetual, ignorable) and **feedback** (buttons squish, cards lift,
   banners pop; fast, tied to a user action or state change). Ambient
   motion must be ignorable on the fiftieth view; feedback motion must
   be instant enough to feel connected to the action.
2. Every animation has a purpose: feedback (confirm an action),
   continuity (connect two states), or guidance (direct attention).
   Decoration for its own sake is rejected.
3. Motion never changes meaning. If the animation is removed, the page
   must still communicate everything.
4. Feedback motion is fast: 100ms to 400ms. Ambient motion is slow:
   6s to 12s loops. Nothing in between wobbles uncertainly.
5. The lab is a tool, not a trailer. Students spend hours here; motion
   that is delightful on first view and annoying on the fiftieth is a
   defect. Challenge pages get the minimum motion needed for feedback;
   the shell gets the warmth.
6. Respect the user: `prefers-reduced-motion` disables ALL motion,
   ambient included, no exceptions.

## 2. Why CSS only (stack verdict, unchanged)

No animation library for the core transformation. GSAP plus ScrollTrigger
(verified free since 3.13) stays on the bench as the documented upgrade
path if scroll-choreographed explainers are ever added. Motion for React
assumes React; Lenis smooth scroll fights precise lab work and adds a
permanent rAF loop for zero lab benefit; Aceternity UI components assume
React plus Tailwind. The clay motion language (squish, lift, drift,
breathe) is fully expressible in CSS keyframes and transitions, which
keeps the zero-dependency, zero-build-step constraint intact.

## 3. The nine animations

All keyframes animate transform and opacity only (compositor-friendly).
Copy-pasteable definitions; durations and easings are tokens, not
one-offs.

### A1. Clay float (ambient)

Zero-gravity drift for background blobs. 8s loop.

```css
@keyframes clay-float {
  0%, 100% { transform: translateY(0) rotate(0deg); }
  50%      { transform: translateY(-20px) rotate(2deg); }
}
.blob-1 { animation: clay-float 8s ease-in-out infinite; }
```

### A2. Clay float delayed (ambient)

Same drift, opposite rotation phase, for visual rhythm. 10s loop.

```css
@keyframes clay-float-delayed {
  0%, 100% { transform: translateY(0) rotate(0deg); }
  50%      { transform: translateY(-15px) rotate(-2deg); }
}
.blob-2 { animation: clay-float-delayed 10s ease-in-out infinite; }
```

### A3. Clay float slow (ambient)

For hero decorative elements that orbit the headline. 12s loop, more
pronounced travel.

```css
@keyframes clay-float-slow {
  0%, 100% { transform: translateY(0) rotate(0deg); }
  50%      { transform: translateY(-30px) rotate(5deg); }
}
```

### A4. Clay breathe (ambient)

Subtle inflation for stat orbs and the capture badge. 6s loop.

```css
@keyframes clay-breathe {
  0%, 100% { transform: scale(1); }
  50%      { transform: scale(1.02); }
}
```

Ambient rules: blobs and orbs only, never text or controls. Travel stays
under 30px so nothing distracts reading. All ambient loops freeze under
reduced motion (section 6).

### A5. Hover lift (feedback)

Interactive elements float toward the viewer on hover.

```css
.clay-card { transition: transform .5s cubic-bezier(.22,1,.36,1),
                         box-shadow .5s cubic-bezier(.22,1,.36,1); }
a.clay-card:hover { transform: translateY(-8px); /* plus deeper shadow */ }
.clay-btn-primary:hover { transform: translateY(-4px); }
```

Values: cards lift 8px over 500ms, buttons lift 4px over 200ms,
pills lift 4px. Hover is enhancement only; nothing load-bearing depends
on it (touch devices get active/focus states instead).

### A6. Active squish (feedback)

The clay signature: pressed elements compress like a toy.

```css
.clay-btn-primary:active {
  transform: scale(.92);
  box-shadow: var(--shadow-clay-pressed);
  transition-duration: .2s;
}
```

200ms, the fastest feedback in the system. Every button and pressable
card gets it. The shadow swap (convex to pressed stack) sells the
physicality more than the scale alone.

### A7. Staggered delays (guidance)

Lists read as sequences, not pop-ins. Two uses:

- Blob choreography: `.animation-delay-2000` (2s) and
  `.animation-delay-4000` (4s) offsets on ambient loops.
- Entrance stagger: module cards and challenge rows fade-rise with
  40ms per-item delays, capped at 8 items, via IntersectionObserver
  adding `.in` once. Elements are visible by default without JS; the
  observer only enhances, never gates. Never stagger scoreboard rows
  (235 rows must paint instantly).

### A8. Scale accents (feedback)

Small celebratory scales, used sparingly:

- Stat orbs: `hover: scale(1.10)` over 300ms.
- Flag capture badge: draws in with a 360ms scale-and-fade.
- Featured bento card: `hover: scale(1.02)`.

Never scale text blocks or form controls; scaling is for orbs, badges,
and decorative shapes.

### A9. Capture pop (feedback, one place only)

The product's core reward moment, used exactly once: the flag capture
banner. Banner scales 0.96 to 1 and fades in over 280ms with
`cubic-bezier(.34,1.4,.64,1)`; the emerald badge breathes once. One
occurrence per capture, no loop, no confetti, no sound. Restrained by
design: a lab instrument acknowledging a measurement, with clay warmth.

## 4. Timing and easing tokens

```css
:root {
  --dur-press: 100ms;   /* squish */
  --dur-fast: 200ms;    /* button hovers, chevrons, focus */
  --dur-base: 240ms;    /* disclosures, small entrances */
  --dur-slow: 500ms;    /* card hovers */
  --dur-ambient-1: 6s;  /* breathe */
  --dur-ambient-2: 8s;  /* float */
  --dur-ambient-3: 10s; /* float delayed */
  --dur-ambient-4: 12s; /* float slow */
  --ease-out: cubic-bezier(.22, 1, .36, 1);
  --ease-in-out: cubic-bezier(.65, 0, .35, 1);
  --ease-pop: cubic-bezier(.34, 1.4, .64, 1); /* capture pop only */
}
```

Rules: feedback entrances use ease-out (arrive decisively); the capture
pop alone may use ease-pop; ambient loops use ease-in-out; nothing uses
linear. Feedback never exceeds 500ms (cards) and mostly lives at 200ms.

## 5. Where motion is restrained: challenge pages

Challenge pages are where students do precise work with attacker tools.
On `/:module/:challenge` routes:

- Ambient blobs are dimmed (opacity halved) or omitted; the page must
  read as a clean workbench.
- No entrance stagger on forms or output wells; they render instantly.
- Motion budget per challenge page: input focus ring, button
  hover/squish, copy-button "Copied" swap, disclosure chevron. Nothing
  else.
- Payload wells and terminal output never animate their content.

The shell (home, module list, scoreboard, capture banner) carries the
clay warmth; the workbench stays quiet. This is the honest tradeoff for
a playful aesthetic on a security tool (see D15).

## 6. Reduced-motion plan

One media query is the single source of truth:

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: .01ms !important;
  }
}
```

In the enhancement script: skip IntersectionObserver reveals (content
renders in final state), skip any JS-driven animation, render progress
fills at final width. The flag capture banner appears instantly and is
still announced via `role="status"`. Reduced motion is a correctness
requirement, not a settings toggle.

## 7. Performance rules

1. Animate transform and opacity only. Blob `filter: blur(80px)` is a
   static filter on a transform-animated element: the blur is computed
   once per element, the animation stays compositor-friendly. Never
   animate the blur radius itself.
2. `backdrop-filter` is used on cards only, never on full-page surfaces;
   keep blurred card count modest on long pages (scoreboard sections).
3. No animation runs above the fold on load except the hero entrance;
   everything else is observer-gated or static.
4. IntersectionObserver with once semantics: unobserve after reveal.
5. The enhancement script is one file, deferred, under 5 KB, optional.
6. Scoreboard: no stagger, no per-row animation. 235 rows paint fast.

## 8. Mobile fallbacks

- Ambient blobs: keep, but reduce to 2 blobs and halve travel distances
  under 480px width; hide the third blob (`display: none`).
- Entrance stagger: disabled under 480px (lists fade in without delay;
  small screens give choreography less room to read well).
- Card hover lift becomes active-state lift on touch (no hover to begin
  with); squish carries the feedback.
- Buttons go full-width for primary CTAs; squish stays.
- Native touch scrolling stays; no scroll hijacking.

## 9. No-JS fallbacks

- All content visible without JS; observer reveals enhance only.
- Blobs: without JS they still drift (pure CSS animations); under
  reduced motion they freeze. If CSS animations are disabled entirely,
  blobs render as static soft color fields, which is acceptable.
- Copy buttons: without JS they degrade to selectable text (the payload
  well is always selectable).
- Scoreboard filter: full list is the default; the filter is progressive
  enhancement.

## 10. Acceptance checklist

- Every animation maps to A1-A9 or is documented as a new primitive with
  purpose and values.
- With prefers-reduced-motion forced, no visible animation occurs except
  instant state changes; blobs are frozen.
- With JS disabled, all content is visible and all tasks completable.
- No feedback animation exceeds 500ms; ambient loops are 6s to 12s and
  touch transform only.
- Only transform and opacity are animated (blur values are static).
- Challenge pages pass the restraint audit in section 5.
- The flag capture moment is perceivable without motion (text plus
  `role="status"` announcement).

## Project notes for later phases

- Per the project's standing rules, visual quality is half the project;
  the lab engine (isolation, challenge verification, reset behavior,
  learning outcomes) matters equally. Motion work must never degrade
  challenge reliability or verification paths.
- Reference UIs: PortSwigger Web Security Academy, HTB Academy, OWASP
  Juice Shop / WebGoat, uiverse.io (hand-port CSS, never vendor), and the
  "AI UI/UX Motion Engine" (evaluated in AGENT_SKILLS_RESEARCH.md).
- "Animaster Leap" and "Hipa UI" remain unverified (see D12); do nothing
  with those names until the owner supplies URLs.
- Visual reviews run through the WeasyPrint PDF to PNG pipeline on the VM
  (curl page, render, attach PNGs); motion states are reviewed as static
  frames plus this written spec, since video review is not in the pipeline.
  Note: WeasyPrint does not render CSS animations; keyframe states are
  reviewed by rendering representative frames (e.g. a card at hover lift
  via a debug class) where the static default misleads.
