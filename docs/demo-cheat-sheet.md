# PenTrix VulnLab: Professor Demo Cheat Sheet (5 minutes)

## Setup (do this BEFORE the professor arrives)

```bash
cd PenTrix-VulnLab
git pull
docker compose up --build
# open http://localhost:3000
```

Keep the terminal visible. Do not run `git pull` during the demo.

## The demo (live)

**1. Home page (30 sec)**
Show the module grid. Say: "29 modules, 235 challenges, every one a small real website with a real bug."

**2. SQL Injection module (30 sec)**
Open the SQL Injection module. Point at the challenge list and the hint ladder.

**3. The exploit (2 min, the star of the show)**
Open the Login Bypass challenge. Say: "This login builds its SQL query by pasting my input straight into it. Watch."
- Username: `admin' -- ` (type exactly this, with the space at the end)
- Password: anything, e.g. `x`
- Click Log in.

The page shows **"Flag captured"** with a `PENTRIX{...}` flag, and it is saved to the scoreboard.

**4. Scoreboard (30 sec)**
Open Scoreboard. It shows 1/235. Say: "Every flag is generated fresh on each install, so students cannot copy flags from GitHub or each other. And shortcuts earn nothing: only a real exploit gets a flag."

**5. Close (30 sec)**
Quick scroll of another module (XSS). Say: "Same pattern across all 29 modules. The roadmap adds break-then-fix mode, kill-chain scenarios, and guided career paths."

## If something goes wrong

- **Page does not load:** check the terminal, the container takes ~20 seconds on first boot. Run `docker compose logs` to see it.
- **Exploit does not work:** retype the username carefully, the trailing space after `--` matters. Or restart fresh: `docker compose down -v && docker compose up --build` (this also generates a fresh set of flags).
- **Professor asks "is it safe to run?":** "Yes. It binds to localhost only, drops container privileges, and is resource-limited. It never touches the internet."

## One-line summary

"PenTrix VulnLab is a training platform with 235 intentionally vulnerable web challenges where every flag must be earned by real exploitation, nothing can be cheated, and nothing leaks from the source code."
