# CYBERSECURITY PLATFORM BENCHMARK: Learning-Design Patterns for PenTrix VulnLab

Date: 2026-10-19. Scope: learning-design patterns only (discovery, paths, difficulty, hints, scoring, reset, remediation, progress). No branding, proprietary content, or visual designs are copied here. Platform facts were verified via web search on the research date; widely known operational details are marked [well-established] where no direct citation was fetched.

## 1. PortSwigger Web Security Academy

- Discovery/categorization: content organized by vulnerability topic (SQL injection, XSS, SSRF, XXE, etc.). Each topic has a topic index page; labs within a topic are ordered Apprentice -> Practitioner -> Expert, i.e. easy to hard inside the topic. Official learning paths exist as curated sequences across topics.
- Learning paths and prerequisites: named learning paths guide learners across topics; within a topic, the Apprentice/Practitioner/Expert ladder acts as an implicit prerequisite chain (e.g. SQLi has 2 Apprentice and 16 Practitioner labs).
- Difficulty progression: three named tiers (Apprentice, Practitioner, Expert) per topic; research-focused newer topics skew advanced. Labs are self-paced, no deadlines.
- Guided vs exploratory: theory-heavy. Each topic ships long-form written material plus videos; each lab gives an explicit goal statement ("To solve the lab, ..."). Exploratory in that the learner must figure out the attack; guided in that theory, examples, and labs are tightly paired.
- Hint system: every lab page carries a "Hint" section plus a full written "Solution" (step-by-step walkthrough) and community video solutions. Hints/solutions are openly visible on the lab page, not gated behind solving.
- Completion/scoring: labs marked complete per account; global leaderboard; Hall of Fame (first solver of each new lab gets named, plus Burp Suite swag). No points per lab beyond completion.
- Reset/lifecycle: lab instances are ephemeral per-user cloud instances that expire; a fresh instance can be launched at any time.
- Remediation teaching: each topic's theory covers how the vulnerability arises and how to prevent it; the Academy is positioned as the interactive successor to "The Web Application Hacker's Handbook".
- Progress tracking: per-account progress across all labs, visible leaderboard.

## 2. Hack The Box Academy

- Discovery/categorization: Library tab lists Modules; each Module is a standalone course on one topic, broken into digestible Sections.
- Learning paths and prerequisites: two path types: Job Role Paths (curricula aligned to real security roles and certifications) and Skill Paths (deep dives on one technical sub-topic). Every module states explicit prerequisites ("A firm grasp of the following modules can be considered prerequisites for successful completion"), e.g. the AD module lists Intro to Academy, Networking, Windows Fundamentals.
- Difficulty progression: 5-tier system (Tier 0 through higher tiers, Fundamental/Easy/Medium/Hard/Insane). Higher tiers mean more depth. Tier 0 modules are effectively free.
- Guided vs exploratory: heavily guided. Sections pair theory with worked examples and command output; learners are told to reproduce examples; no time limits and no grading ("You can start and stop the module at any time and pick up where you left off"). Each module ends with a practical guided lab and a skills assessment.
- Hint system: guidance is embedded in the material itself rather than a separate hint ladder; assessments test whether the learner internalized it.
- Completion/scoring: completing sections, exercises, and the skills assessment marks the module complete; Cubes (platform currency) are awarded back on completion. Job Role Paths lead to certification exams (voucher via subscription or one-off purchase).
- Reset/lifecycle: interactive sections run on live targets (browser-based Pwnbox or own VM via VPN/Docker); targets can be respawned. Purple modules require the attack to happen first to generate logs/traffic/memory captures for the defensive analysis half, so target lifetime management matters.
- Remediation teaching: present mainly via Purple (defensive) modules and blue-team content: after attacking, learners do forensic analysis with a preinstalled DFIR toolset. Searchable by MITRE ATT&CK technique.
- Progress tracking: per-module completion feeds path progress; Cubes balance acts as visible progress currency.

## 3. TryHackMe

- Discovery/categorization: content units are "rooms", searchable in a large catalog (1000+ rooms). Rooms are typed: Walkthrough (guided tutorial), Challenge (CTF, no help), plus full Machines. Learning Paths are curated room sequences for job roles (Pre-Security, Complete Beginner, Offensive Pentesting, Junior Penetration Tester, Cyber Defense).
- Learning paths and prerequisites: paths are the primary onboarding tool; within a path, rooms run in a recommended order so each teaches what the next assumes. Community roadmaps fill the gaps where the catalog order alone confuses beginners.
- Difficulty progression: room difficulty ratings (Easy/Medium/Hard etc.) plus the Walkthrough-vs-Challenge split: guided first, unassisted second.
- Guided vs exploratory: the sharpest split of any platform here. Walkthrough rooms teach step by step; Challenge rooms give a target and nothing else. Rooms are split into Tasks; each task mixes short theory with questions.
- Hint system: hints available per task, but using them impacts the score. Answers are of two kinds: answers found in the reading, and flags (`THM{...}`) found by hacking the machine.
- Completion/scoring: correct answers earn points feeding global rank and league tables; badges and streaks add engagement layers. Hint usage reduces score, creating a real tradeoff.
- Reset/lifecycle: deployable VMs per room (AttackBox in browser or own machine via OpenVPN); machines can be reset/terminated from the room UI; free accounts get limited daily AttackBox time.
- Remediation teaching: lighter than WebGoat; defensive paths (SOC, threat hunting, SIEM) teach the blue side in separate rooms rather than per-vulnerability remediation.
- Progress tracking: per-room completion, path progress bars, badges, global leaderboard, streaks.

## 4. OWASP Juice Shop

- Discovery/categorization: the Score Board lists every challenge with a short description. Challenges are clustered by difficulty (1 to 6 stars); by default only the 1-star block is unfolded. Descriptions range from near-explicit hacking instructions to vague hints. Categories align with OWASP Top 10 classes (Injection, XSS, Broken Access Control, etc.).
- Learning paths and prerequisites: none. The product is deliberately non-linear; the player chooses. A small subset of challenges has scripted "Hacking Instructor" tutorials with a recommended order.
- Difficulty progression: 1-6 star ratings, "continually adjusted over time based on user feedback". Ratings are explicitly framed as pacing tools: a 5-6 star challenge should be expected to take many attempts; a 1-2 star challenge taking long signals a wrong approach.
- Guided vs exploratory: almost purely exploratory. The app is a normal-looking shop; the player hunts vulnerabilities. No per-challenge walkthrough in the app itself (the companion book "Pwning OWASP Juice Shop" is external).
- Hint system: the best-designed of the five. Each challenge declares 2-3 progressive hints (more than 6 discouraged); hover the "unsolved" label on the Score Board to reveal a hint; a book icon deep-links to the matching section of the companion guide. Hints are data-driven: the single source of truth is `data/static/challenges.yml`, each entry carrying name, category, description, difficulty, hints, tags, and `mitigationUrl`.
- Completion/scoring: solved/unsolved state per challenge; percent progress bar plus absolute counts per difficulty; built for group-hacking competition. A CTF export mode converts difficulty to points (1 star = 100, 2 = 250, 3 = 450, 4 = 700, 5 = 1000, 6 = 1350) with paid hints costing 10%/20% of the challenge value.
- Reset/lifecycle: restarting the app resets state; challenges can be retried freely; hiding solved challenges reduces distraction.
- Remediation teaching: every challenge carries a `mitigationUrl` pointing at the relevant OWASP Cheat Sheet, teaching the fix alongside the exploit.
- Progress tracking: Score Board is the progress tracker; also exportable to CTF score servers (FBCTF and others).

## 5. OWASP WebGoat

- Discovery/categorization: lessons grouped by vulnerability type (Injection, XSS, Access Control, etc.), not ordered by difficulty. Community guidance explicitly says lessons are nonsequential and learners should jump around freely.
- Learning paths and prerequisites: none built in; instructors assemble assignments from lessons (e.g. university courses assign specific numbered lessons). Assumes the learner has read background material (OWASP Top 10) first.
- Difficulty progression: none formal; lessons vary in difficulty and each exposes full source code, so difficulty is self-regulated.
- Guided vs exploratory: guided at the lesson level. Each lesson has a Lesson Plan (theory), an attack surface, a Hints button, Show Params / Show Cookies / Show Java (view the actual source) buttons, and an optional full Solution.
- Hint system: per-lesson Hints button plus solution on demand; the "Show Java" source view is itself a hint mechanism unique to WebGoat.
- Completion/scoring: a score card shows completed lessons; used in classrooms with screenshots as assignment submissions.
- Reset/lifecycle: run locally or in Docker; restart the app to reset lesson state.
- Remediation teaching: the strongest of the five at the lesson level. Lesson plans cover prevention/mitigation, and the source-view design means learners see both the vulnerable code and how it should be written.
- Progress tracking: per-user score card.

## Comparison matrix

| Dimension | PortSwigger | HTB Academy | TryHackMe | Juice Shop | WebGoat |
| --- | --- | --- | --- | --- | --- |
| Lab discovery | Topic index, Apprentice/Practitioner/Expert per topic | Library of Modules + Sections | Room catalog (1000+), typed rooms | Score Board, difficulty-clustered | Lesson menu grouped by vuln type |
| Learning paths | Named paths across topics | Job Role Paths vs Skill Paths | Curated paths per job role | None (deliberate) | None (instructor-assembled) |
| Prerequisites | Implicit tier ladder | Explicit per-module prereq lists | Implicit path ordering | None | Assumed background reading |
| Difficulty model | 3 tiers per topic | 5 tiers, Fundamental to Insane | Room ratings + Walkthrough/Challenge split | 1-6 stars, feedback-adjusted | None formal, self-regulated |
| Guided vs exploratory | Theory + goal, explore the attack | Heavily guided, reproduce examples | Both: Walkthrough vs Challenge rooms | Exploratory, minor tutorial subset | Guided lesson plans + attack |
| Hint system | Open Hint + full Solution per lab | Embedded in material | Hints cost score | Progressive hint ladder, hover-to-reveal, book deep-links | Hints button + source view + solution |
| Completion/scoring | Completion + leaderboard + Hall of Fame | Cubes back, path completion, certs | Points, rank, badges, streaks; hints reduce score | Solved/unsolved, % bar; CTF points with paid hints | Score card |
| Reset/lifecycle | Ephemeral per-user instances | Respawnable targets, Pwnbox | Resettable VMs, AttackBox | App restart; free retry | App restart |
| Remediation teaching | Prevention in topic theory | Purple/defensive modules, DFIR half | Separate defensive paths | mitigationUrl per challenge to OWASP Cheat Sheets | Lesson plans + vulnerable vs fixed source |
| Progress tracking | Account-wide lab progress | Module/path progress + Cubes | Room/path progress, leaderboard | Score Board % and per-difficulty counts | Per-user score card |

## Derived product principles for PenTrix VulnLab

Patterns worth adopting, mapped to PenTrix's reality (29 modules, 244 vulns, session-based flags, Express template strings):

1. **Difficulty-clustered, progressively disclosed catalog (Juice Shop).** Keep the module cards, but add per-vuln difficulty stars and collapse harder tiers by default so beginners are not overwhelmed. PenTrix already records Easy/Medium/Hard per vuln; surface it and cluster it.
2. **Declarative challenge catalog as single source of truth (Juice Shop `challenges.yml`).** PenTrix's module contract already exports structured metadata (`vulns[]` with id, name, difficulty, hint, how). Aggregate it at build/boot into one JSON catalog that drives the home page, scoreboard, paths, and hints, instead of hand-maintained lists.
3. **Feedback-adjusted difficulty (Juice Shop).** Treat Easy/Medium/Hard as initial values; plan to adjust from real solve data (solve rate, time-to-flag, hint usage) once the platform collects it.
4. **Progressive hint ladder with an explicit hint/score tradeoff (Juice Shop + TryHackMe).** PenTrix has one `hint` per vuln today. Expand to 2-3 escalating hints per vuln; in any competitive mode, hint usage should cost points (TryHackMe model) so there is a real decision.
5. **Remediation link on every vuln (Juice Shop `mitigationUrl`, WebGoat lesson plans).** Add a "the fix" element to the contract: after a flag is captured, show the secure pattern (e.g. parameterized queries) and link the relevant OWASP Cheat Sheet. Teaching the fix is what separates a training platform from a CTF.
6. **Guided vs exploratory modes (TryHackMe).** Keep the current exploratory challenge pages, but add an optional guided track: a small set of scripted walkthroughs ("Hacking Instructor" style) for the first module a learner touches, so absolute beginners are not dropped into a blank form.
7. **Learning paths with explicit prerequisites (HTB Academy).** Add 3-4 curated paths over the existing 29 modules (e.g. "Web Fundamentals": http -> auth -> session -> sqli -> xss; "API Attacker": api -> jwt -> oauth -> cors -> jsonp), each module page listing "do these first" prerequisites in HTB style. No new content required, only ordering metadata.
8. **End-of-module skill check (HTB Academy).** Add one unhinted "prove it" challenge per module (a variant of a taught vuln) that must be solved to mark the module complete. This is the closest PenTrix-native equivalent of a skills assessment.
9. **Solutions after solve, never before (PortSwigger).** PenTrix has SOLUTIONS.md with full walkthroughs. Link the per-vuln solution from the flag-captured state only, PortSwigger-style, instead of leaving it as a separate repo file.
10. **Completion states and progress bars (all five).** PenTrix has done/total counters and a scoreboard. Extend to: per-module progress bars, a global percent, solved/unsolved filtering on module pages (Juice Shop's status filter), and a first-solver or fastest-solver recognition (PortSwigger Hall of Fame) for classroom deployments.
11. **One-click reset per challenge (TryHackMe, PortSwigger).** Some PenTrix vulns mutate state (uploads, race conditions, stored XSS). Add a per-module/per-vuln reset that restores seeded state so learners can retry cleanly without restarting the app.
12. **Show-the-source as a teaching tool (WebGoat).** Where the module contract already requires `// VULN:` markers, consider an opt-in "view vulnerable code" reveal after solving, so learners connect the exploit to the exact flawed lines, WebGoat "Show Java" style.
13. **Scoring weighted by difficulty (Juice Shop CTF, TryHackMe).** If PenTrix adds points, weight by difficulty tier and deduct for hints used; raw flag counts treat a Hard SSRF the same as an Easy reflected XSS, which misleads learners about their skill.
14. **Keep the catalog honest about what is guided (WebGoat's nonsequential lesson warning).** Where PenTrix modules do not build on each other, say so; where they do (e.g. jwt before oauth), encode it as prerequisites rather than letting learners discover it by failing.

## What could not be verified

- Exact current room/path counts and pricing on TryHackMe and HTB Academy change frequently; figures above are structural, not numeric, for that reason.
- PortSwigger's current policy on whether solutions are visible before solving was inferred from public lab pages (Hint/Solution sections are present in the page text); any solve-gating on the live site was not tested with an account.
- Juice Shop's "Hacking Instructor" tutorial coverage (which challenges have scripted tutorials) was not enumerated.
- No accounts were created and no labs were executed; this benchmark is about learning design, verified from documentation and help centers, not from hands-on play.
