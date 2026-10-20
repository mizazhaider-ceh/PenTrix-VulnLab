# Running PenTrix VulnLab in a classroom

This lab is intentionally vulnerable. Read the safety warning first, then
use the minimum tooling below to run a class on it.

## Safety and isolation

The default deployment is a single local container bound to localhost
only (see `docker-compose.yml`). Never expose the lab to a public
network: it is a training target, not a service.

For a class, do not share one instance between students (see D14 in
`docs/roadmap/DECISIONS.md`): run **one container per student**, each with
its own data volume, on a private bridge network. Per-student volumes keep
one student's work and one student's resets away from everyone else's.
Drop container capabilities and set CPU/memory limits (the compose file
already caps at 1 CPU / 512 MB per container; keep something equivalent
for every student instance). A sketch of this setup is the D14 reference;
the exact orchestration is your choice, but per-student instances plus
per-student volumes is the non-negotiable part.

Set a private `SESSION_SECRET` for every deployment. The compose file
ships the variable commented out and the app falls back to a committed
dev secret with a startup warning; that fallback is fine for a solo lab
and unacceptable for graded or shared use.

## How progress works

A student's progress is bound to their browser session (one session
cookie). There are no accounts and no roster: the scoreboard page always
shows the progress of whoever is browsing it.

Consequences the instructor must know:

- Clearing cookies, switching browsers, or losing the cookie jar resets
  the scoreboard to 0. There is no recovery.
- Restarting the lab rotates per-boot secrets and wipes shared lab state
  (race state, caches, one-time tokens). The scoreboard shows a restart
  notice on the next page load for any session that survived the reboot,
  and the scoreboard itself says progress resets on restart.
- Every flag box has a Copy button. Tell students to record each flag as
  they earn it; that is the only progress record that survives a lost
  session.

## Progress export (gradebook)

Each student exports their own scoreboard: the scoreboard page has an
**Export scoreboard (CSV)** button, or `GET /scoreboard/export.csv`
directly. Columns: module id, module name, challenge id, challenge name,
difficulty, status (`captured` / `not captured`). The kill-chain
scenarios are included as rows with module id `scenario`.

Collect one CSV per student for your gradebook. There is no instructor
dashboard and no central roster; the lab cannot tell you whose CSV is
whose, so pair exports with a classroom submission step that does.

## Reset procedure

There is no per-student reset button and no instructor console. Use these:

- **Student self-reset (supported):** clear cookies for the lab origin,
  or open the lab in a fresh browser profile or private window. That
  starts a brand-new session with 0 captures.
- **Single shared instance, one student misbehaving:** have the student
  do the self-reset above. There is no supported way to reach into the
  lab and delete one session; do not improvise one.
- **Full reset of a student instance:** stop the container, delete its
  data volume contents, start again. Everything is re-minted on boot:
  session state, challenge flags, and the install identity used by
  certificate codes.

curl-based students (Burp-free workflows) must keep their cookie jar in
one place and use one process per jar. Two parallel `curl -c jar` writes
clobber each other: the last writer wins and the surviving jar can point
at a fresh empty session, which reads as 0/201 with a changed session id.
Keep jars out of `/tmp` (host reboots wipe it) and never share one jar
file across parallel processes. Parallel bursts against the lab itself
are safe: the session store merges captured flags across concurrent
requests, so a race-module burst cannot erase earlier captures.

## Certificates and identity

Career-path certificates print a verification code. The code is always
bound to the install (the machine that issued it); it is **not**
identity-bound unless the student entered a name or handle when
generating the certificate. A code generated without a name is identical
for every student on the same install, and the verify page says so.

Classroom rule: require students to enter their name on the certificate
form. Then the code is derived from install plus path plus that name,
and the verify page checks the same name. Treat unnamed certificates as
unverifiable proof of individual work.

## Checklist before week one

1. One container per student, private network, per-student volume,
   capability drops, resource limits (D14).
2. Private `SESSION_SECRET` set on every instance; confirm the startup
   warning about the fallback secret is gone.
3. localhost-only binding confirmed; no public exposure.
4. Students briefed: record every flag, keep the cookie jar safe, never
   share one jar across parallel processes, exports are per-student CSVs.
5. Certificate policy set: names required for graded paths.
