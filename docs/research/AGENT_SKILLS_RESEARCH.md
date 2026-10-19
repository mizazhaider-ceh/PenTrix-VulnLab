# AGENT SKILLS RESEARCH: UI/Frontend Agent Skills for PenTrix VulnLab

Date: 2026-10-19. All facts below were verified live via GitHub web pages and the GitHub API on the research date. Hypotheses and inferences are marked.

## Context: what this is for

PenTrix VulnLab is a plain Node + Express 4 app with server-rendered template strings (`lib/page.js`), one small stylesheet, no frontend framework, no build step, no new npm dependencies allowed for module authors. Any "agent skill" recommendation must therefore be:

1. Useful as agent guidance (skills are markdown docs, not runtime code), since skills do not ship into the product.
2. Compatible with plain HTML/CSS/vanilla JS output, no React, no Tailwind build, no npm install required to apply.
3. Worth the install for the actual work: premium visual redesign of the shell (home, module pages, scoreboard) and better challenge-page UX.

## Comparison table

| Repo | Real URL (verified) | Purpose | License | Maintenance (last commit, verified) | Install method | Compatibility with Express + server-rendered stack | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| JustineBijuPaul/frontend-ai-skills | https://github.com/JustineBijuPaul/frontend-ai-skills | 70 SKILL.md files for AI coding agents: frontend architecture, React/Next.js, animation, 3D/WebGL, a11y, performance, design-to-code | MIT | 2026-09-04 (all 86 commits same day as repo creation; 1 star, 0 forks) | Clone, then `install/install.sh --claude --all` (or per editor: Cursor, Claude Code, OpenCode, Codex); also `--category` for subsets | Low. The vast majority of skills target React, Next.js, TypeScript, GSAP, Framer Motion, Three.js, R3F. Only 05-html / 06-css / 08-ui-ux-design / 11-accessibility would apply to template-string HTML. As markdown guidance nothing breaks the stack, but the fit is poor for a no-framework app. | NOT RECOMMENDED |
| OpaceDigitalAgency/ai-ui-ux-motion-engine | https://github.com/OpaceDigitalAgency/ai-ui-ux-motion-engine | One canonical Agent Skill for website design, UI/UX, motion graphics, 3D web experiences, cinematic scroll, video storytelling; multi-pass design workflow with accessibility/SEO quality gates | MIT | 2026-07-28 (v1.7.0 release; 11 commits total, all within ~2 days of 2026-07-26 creation; 5 releases, 3 stars) | Cloned repo or downloaded release, installers copy `skills/ai-ui-ux-motion-engine/` into agent discovery paths (Codex, Claude Code, Cursor, Copilot, Windsurf, etc.) | Low. Oriented toward marketing websites, landing pages, SaaS homepages, portfolios, and cinematic 3D scroll experiences, with explicit React/Next.js, Framer Motion, Three.js references in its README workflow. PenTrix is a functional training app, not a marketing site; cinematic motion is the wrong tool. | NOT RECOMMENDED |
| aladicf/better-web-ui | https://github.com/aladicf/better-web-ui | Opinionated agent skills library for design judgment: generate UI directions (`add-ui`), critique UX (`critique`), accessibility/performance audits (`audit`), onboarding, motion, design systems | CUSTOM (see below, NOT MIT) | 2026-05-21 (last commit adds "Maintenance Mode" notice; 39 commits; author shifted active development to a separate React project `better-react-web-ui`; 43 stars, 3 forks) | `npx skills add aladicf/better-web-ui --agent <agent>` (skills CLI), optional `--skill` selector for subsets, `-g` for global | HIGHEST of the four. Explicitly framework-agnostic and "stack-aware": README lists plain HTML, CSS, and JavaScript alongside React/Vue/Svelte, and agents are told to match the existing stack first. Pure markdown guidance: zero runtime deps, zero build step impact, works with template-string HTML and vanilla CSS. | RECOMMENDED (selective subset only) |
| hueyexe/frontend-agent-skills | https://github.com/hueyexe/frontend-agent-skills | 9 skills on UX design judgment: forms/inputs/checkout, information architecture/navigation, interaction patterns, visual composition, UX writing/content design, usability foundations, accessibility, design systems, UX research | MIT | 2026-08-02 (6 commits, created 2026-04-30; 21 stars, 4 forks) | `npx skills@latest add hueyexe/frontend-agent-skills`, optional `--skill <name>` for subsets | Medium. Framework-agnostic design guidance (no framework assumptions visible in README structure). Most relevant skills for PenTrix: forms-inputs-checkout (challenge form UX), ux-writing-content-design (error/empty states, flag copy), accessibility-inclusive-design. All markdown, no build impact. | OPTIONAL, second pick only if UX writing is a priority |

## Detailed findings

### 1. JustineBijuPaul/frontend-ai-skills

- Verified real at https://github.com/JustineBijuPaul/frontend-ai-skills (page title: "Modular library of 70 frontend skills for AI coding agents").
- Contents: 70 numbered `SKILL.md` folders: core frontend (01-20: architecture, React, Next.js, TypeScript, HTML, CSS, responsive, UI/UX, design systems, components, a11y, forms, APIs, state, data fetching, frontend security, performance, image/video optimization, browser APIs), animation & interaction (21-40: GSAP, ScrollTrigger, Lenis, Framer Motion, Motion for React, scroll storytelling), 3D/media/motion quality (41-53: Three.js, R3F, WebGL, GLSL), quality/product/AI workflow (54-70).
- License: MIT (verified on repo details).
- Maintenance: 86 commits, but all dated 2026-09-04 (the creation day), confirmed via GitHub API (`commits?per_page=3` shows latest 2026-09-04T16:54:19Z). One star, zero forks. Effectively a one-day snapshot; no evidence of ongoing maintenance since.
- Install: `git clone`, then `./install/install.sh --claude --all` (or --cursor, --opencode, --codex, --agents, --editors), with `--category` filters (core, animation, cinematic, 3d, quality) and remote one-liners. Skills are markdown; nothing executes in the app.
- Compatibility: nothing technical blocks it (docs only), but content fit is poor. A 70-skill React/Next.js/GSAP/Three.js library is mostly dead weight for an app that renders `lib/page.js` template strings. Only the HTML/CSS/a11y skills map to PenTrix work, and those are general knowledge any frontend-fluent agent already has.
- Verdict: not recommended. Bulk without relevance.

### 2. OpaceDigitalAgency/ai-ui-ux-motion-engine

- Verified real at https://github.com/OpaceDigitalAgency/ai-ui-ux-motion-engine (public template repo).
- Contents: a single canonical skill folder `skills/ai-ui-ux-motion-engine/` plus plugin manifests (`.claude-plugin`, `.codex-plugin`), installers in `scripts/`, platform docs in `platforms/`. The README describes a multi-pass design workflow: brief/baseline, reference extraction, seven-line visual direction, motion architecture, multi-pass implementation, accessibility/performance/SEO quality gates. Latest source version v1.7.0; 5 releases.
- License: MIT (verified on repo details).
- Maintenance: 11 commits, created 2026-07-26, last commit 2026-07-28 ("Release v1.7.0 enforced cinematic intent gates") confirmed via GitHub API. 3 stars, 0 forks. Dormant since late July.
- Install: clone/download release; installers copy the skill folder into agent discovery paths for Codex, Claude Code, Cursor, Copilot, Antigravity, Gemini CLI, Windsurf, Cline, Roo Code, OpenCode, Amp, Zed, goose.
- Compatibility: README use cases are marketing sites, landing pages, SaaS websites, portfolios, cinematic 3D scroll, GSAP/ScrollTrigger, Framer Motion, Three.js, watch-style product films. The directive's goal is a premium, professional training-app shell, not a cinematic marketing experience. Forcing this skill onto the VulnLab would push toward exactly the decorative "wow" effects the codebase's premium-directive posture should avoid in challenge pages (where clarity and speed matter more than motion).
- Verdict: not recommended. Wrong genre for this product.

### 3. aladicf/better-web-ui (the one pick)

- Verified real at https://github.com/aladicf/better-web-ui. Self-description: "an opinionated Agent Skills library for developers who ship code that works and would like the UI to stop looking like a Midjourney prompt of 'modern SaaS dashboard.'" Skills: `setup`, `add-ui`, `critique`, `audit`, `animate`, `onboard`, `optimize`, plus meta/setup/review/finishing categories.
- License: CUSTOM, not MIT. The LICENSE file says it is "based on the MIT License, but it adds additional restrictions requiring this project and its forks to remain free, source-available, and not sold as a proprietary product." Added conditions include: redistributors must publish complete source under the same license; may not sell as a closed-source or paid product; may not claim it as an exclusive product. GitHub's license detector reports "Other (NOASSERTION)". Practical implication: fine for internal guidance use (skills are used as instructions, not shipped), but do not vendor modified copies into a commercial product or sell it as part of a paid offering.
- Maintenance: 39 commits, created 2026-04-08. Last commit 2026-05-21 adds a "Maintenance Mode" notice to the README (confirmed via GitHub API): "This repo remains available and will continue supporting all web frameworks and tools. While the information here stays up to date, my active development focus has shifted to better-react-web-ui, a React + Shadcn + TailwindCSS project." 43 stars, 3 forks. Expect no future updates; treat as a finished, stable artifact.
- Install: `npx skills add aladicf/better-web-ui --agent codex --agent cursor --agent github-copilot --agent opencode` (or a single `--agent`); subsets via `--skill add-ui --skill critique`; `-g` for global. The README recommends installing to Codex/Cursor/Copilot/OpenCode paths, all sharing `.agents/skills/` as project scope.
- Compatibility: the highest of the four for this stack. Explicitly framework-agnostic, works with "plain HTML, CSS, and JavaScript", and instructs agents to match the existing stack first. All skills are markdown guidance: no npm packages, no build step, no touching `app.js`/`lib`/`public` needed. The `/setup` step writes project context (`.better-web-ui.md`), which can record the PenTrix constraints (no deps, template strings, dark theme).
- Caveats: maintenance mode (stable but frozen); the skill library is taste-oriented guidance, so output quality still depends on the agent using it; it will not write the CSS for you, it guides the writing.
- Verdict: RECOMMENDED, but install selectively. Suggested subset: `setup` (project context), `add-ui` (UI directions for the new shell), `critique` (review existing pages), `audit` (a11y/performance pass). Skip the motion/animation skills for challenge pages.

### 4. hueyexe/frontend-agent-skills

- Verified real at https://github.com/hueyexe/frontend-agent-skills. 9 skills, each `SKILL.md` plus a `references/` folder (anti-patterns, checklists, decision-prompts, principle-cards).
- License: MIT (verified).
- Maintenance: 6 commits, created 2026-04-30, last commit 2026-08-02 ("Wire reference files into all skills and normalize reference titles") confirmed via GitHub API. 21 stars, 4 forks. Small, quiet, likely stable.
- Install: `npx skills@latest add hueyexe/frontend-agent-skills`, optional `--skill` selector; works with Claude Code, Cursor, OpenCode, Kiro.
- Compatibility: framework-agnostic UX guidance, markdown only. The skills most relevant to PenTrix are forms-inputs-checkout (many challenge pages are forms: login, search, upload), ux-writing-content-design (hints, error messages, empty states, success/flag copy), and accessibility-inclusive-design. No build impact.
- Verdict: optional second pick. If the transformation team wants a second skill, install only the three relevant skills above. Do not install all nine; the research/testing and design-system-governance skills are overhead for this app.

## Aceternity UI spelling verification

- Correct name: "Aceternity UI". Official site: https://ui.aceternity.com (verified live via search; result titles read "Aceternity UI, React & Tailwind CSS Component Library").
- It is a React + Tailwind CSS (+ Motion/Framer Motion) component library by Manu Arora, distributed as copy-paste TSX components via the shadcn CLI registry. It is NOT an AI agent skill and has no skill format, no install.sh, no SKILL.md.
- Compatibility with PenTrix stack: poor without a stack change. Components require React/Next.js and Tailwind CSS (plus Motion). Adopting them in the VulnLab would require adding a React renderer and a Tailwind build step, which directly violates the module contract ("Do not add npm dependencies", no build step). Individual components could in theory be hand-ported to vanilla HTML/CSS/JS, but that defeats the purpose of a copy-paste library and adds licensing review per component.
- Similarly named libraries: no other similarly spelled project of note was found; the main confusion risk is mistaking it for an "agent skill", which it is not.
- Verdict: not usable for this stack as-is. Mentioned only to close the directive's open question.

## Recommendation

Adopt ONE of the four: **aladicf/better-web-ui**, installed selectively (`setup`, `add-ui`, `critique`, `audit`) into the project agent skills path, and record PenTrix's constraints (template strings, vanilla CSS, no deps, no build step) via `/setup`. This gives the redesign agents structured design judgment matched to the actual stack, with zero runtime or build impact.

Do not adopt the other three: JustineBijuPaul (React-heavy, one-day snapshot), Opace (marketing-site/cinematic genre mismatch), Aceternity UI (not a skill; requires React + Tailwind build). Optionally add hueyexe's three UX skills (forms, UX writing, accessibility) later if challenge-page copy and form UX become a focus.

## What could not be verified

- Skill content quality beyond the README outline: SKILL.md bodies were not read in full (README-level verification only), so per-skill writing quality is unassessed.
- Whether any of these repos have community adoption beyond star counts: issue trackers and PR activity were not reviewed.
- Long-term maintenance intent for hueyexe and JustineBijuPaul: last-commit dates are reported; nothing more is claimed about their futures.


## Addendum 2026-10-19: mystery references + staged install plan

### A. Mystery reference verdicts

**"Animaster Leap": could not be verified as a distinct product.**

- Web search, the Vercel skills registry (`npx skills find animaster` returned only unrelated animation tools, no match), and IG/Threads/Facebook posts contain no repo, skill, site, or product named "Animaster Leap".
- Closest real product: **Animmaster Lib** (spelled with a double m), site animmasterlib.dev, marketed as a "300 PRO components" animated UI component library combining WebGL and GSAP from "Animmaster Studio". Announced in an abduzeedo blog post dated 2026-07-13 (author prya), and promoted in IG/Threads videos as "250+ animated components for scroll effects, mouse interactions, hero sections" alongside Skiper UI and Vengeance UI. Those social posts use variant spellings: "Animaster Live", "Animaster Lab", "Animaster Lib". No "Leap" edition, plan, or product was found anywhere.
- Inference (marked): "Leap" is most likely a misremembering of one of those name variants, or of "Animmaster Lib" itself. This is not confirmed; ask the owner for a URL if the reference matters.
- Usability for PenTrix: not usable as an agent skill (it is a component library, not a skill). Its components assume modern web builds with WebGL/GSAP and would conflict with the no-deps, no-build-step module contract. Best case it serves as visual inspiration; hand-porting its components to vanilla CSS defeats its purpose.

**"Hipa UI": could not be verified at all.**

- No repo, skill, site, or product under this name exists. Web search results are dominated by HIPAA healthcare compliance; `npx skills find hipa` in the skills registry returned only unrelated AWS/GPU samples; social search found zero mentions.
- Closest-sounding real projects: HyperUI (hyperui.dev, free MIT copy-paste Tailwind components, ~12k stars) and shadcn/ui. Both are component libraries (React/Tailwind oriented), not agent skills, and neither matches the name. This is a phonetic guess only, not a verified identity.
- Verdict: unverifiable. Treat as a typo or misremembered name until the owner supplies a URL. Not usable for this project as stated.

### B. Staged install plan (Phase Two: nothing below has been run; all commands staged for parent review)

Run from `~/workspace/pentrix-vulnlab`. Preview any repo first with `npx skills add <owner/repo> --list`.

**1. better-web-ui subset (`setup`, `add-ui`, `critique`, `audit`), project-local:**

```
npx skills add aladicf/better-web-ui \
  --agent codex --agent cursor --agent github-copilot --agent opencode \
  --skill setup --skill add-ui --skill critique --skill audit -y
```

- The four `--agent` values come from the repo README's own install table; they share the project-scope path `.agents/skills/`, so the CLI writes one shared copy into `~/workspace/pentrix-vulnlab/.agents/skills/`. Project scope is the default; `-y` skips confirmation prompts (both verified against the README and `npx skills --help`, run live).
- After install, run `/setup` in a coding session so the skill records the PenTrix constraints (template strings, vanilla CSS, no deps, no build step) into `.better-web-ui.md`.
- License note: CUSTOM (GitHub reports NOASSERTION; MIT base plus restrictions against selling it as a proprietary product). Internal use as agent guidance is fine; do not vendor modified copies into a commercial product.

**2. hueyexe optional three skills (forms, UX writing, accessibility):**

```
npx skills add hueyexe/frontend-agent-skills \
  --agent codex --agent cursor --agent github-copilot --agent opencode \
  --skill forms-inputs-checkout --skill ux-writing-content-design --skill accessibility-inclusive-design -y
```

- Skill folder names verified live against the repo root listing. MIT licensed. Same project-local `.agents/skills/` target as above.

**3. frontend-ai-skills selective subset (staged for owner decision; the full set stays out):**

- Verified skill folder names from the repo catalog: `05-html`, `06-css`, `08-ui-ux-design`, `11-accessibility`.
- This repo does NOT use the `npx skills` CLI; it ships its own `install/install.sh`. Per-skill install works: `--category` accepts a single skill folder name (verified in `install/install.sh`, line 47: "or a skill folder name"), and repeated invocations are additive.

```
git clone --depth 1 https://github.com/JustineBijuPaul/frontend-ai-skills.git /tmp/frontend-ai-skills
cd ~/workspace/pentrix-vulnlab
for s in 05-html 06-css 08-ui-ux-design 11-accessibility; do
  /tmp/frontend-ai-skills/install/install.sh --agents-project --category "$s"
done
```

- `--agents-project` targets `./.agents/skills` in the current directory (verified in `install.sh`). Default mode copies only `SKILL.md`; add `--symlink` if the clone will be kept, so skills update on `git pull`.
- Why the full set stays out: 70 skills, almost all React/Next.js/GSAP/Three.js; one-day snapshot (all 86 commits on 2026-09-04), 1 star, no ongoing maintenance. Bulk without relevance to a template-string, no-framework stack.
