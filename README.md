# Build Secure 24 — Participant Starter Repository

**Abhedya — VBIT Cybersecurity Forum, Vignana Bharathi Institute of Technology, Hyderabad**

Welcome to the official Build Secure 24 starter repository.

---

## 1. Challenge Overview

- **Schedule**: October 5, 2026, 11:00 AM IST to October 6, 2026, 11:00 AM IST
- **Duration**: Exactly 24 Hours
- **Submission Deadline**: October 6, 2026, 11:00 AM IST (`2026-10-06T11:00:00+05:30`)
- **Team Size**: Exactly 2 or 4 participants per team (teams of 1, 3, or >4 are not permitted)
- **Core Requirement**: All project code must be created live during the 24-hour hackathon. Importing pre-built or third-party repositories is strictly prohibited.

---

## 2. Repository Structure

```
├── AGENTS.md                  ← AI agent behavioral contract & logging gate
├── README.md                  ← This file
├── PARTICIPANT_RULES.md       ← Competition rules
│
├── docs/                      ← Autonomous documentation layer
│   ├── APPROACH.md            ← Problem breakdown & architecture approach
│   └── logs.txt               ← Turn-by-turn prompt, file location & timeline log
│
├── metadata/                  ← Submission metadata
│   ├── team.yaml              ← Team information (2 or 4 members)
│   └── submission.yaml        ← Final submission details
│
├── src/                       ← Application source code directory
└── deployment/                ← Deployment configuration directory
    └── README.md              ← Deployment record
```

---

## 3. Getting Started

### Step 1: Team Registration & GitHub Repository Setup
1. Create a new GitHub repository for your team's project.
2. Fill in `metadata/team.yaml` with your assigned Team ID, team name, your newly created GitHub repository URL (`team.repository`), and all 2 or 4 member details.

### Step 2: AI Agent Onboarding
When you open this repository in an AI coding assistant (Cursor, Windsurf, Claude Code, Copilot, ChatGPT, etc.):
- The agent will read `AGENTS.md`, greet your team, recite the competition ground rules, display the remaining time until **October 6, 2026, 11:00 AM IST**, and collect your `I agree` confirmation.
- Once confirmed, the agent records your team details and GitHub repository URL, and configures your Git remote origin.
- The agent will **automatically log every prompt, the full agent response, the Git commit SHA, exact file changes, and timeline** in `docs/logs.txt` as you build.

### Step 3: Build & Ship with Continuous Push
- Author your application code inside `src/`.
- After each prompt, changes are committed with the exact commit SHA recorded in `docs/logs.txt`, and can be pushed directly to your team's GitHub repository (`git push origin main`).
- Document your technical approach in `docs/APPROACH.md`.
- Deploy your application and record live details in `deployment/README.md`.
- Update `metadata/submission.yaml` with your final commit SHA before the **October 6, 2026, 11:00 AM IST** deadline.

---

## 4. Multi-Device Team Collaboration

All 4 team members can work simultaneously across separate laptops:

1. **Clone**: Every teammate clones your team's GitHub repository to their device.
2. **Syncing Progress**:
   - When one teammate finishes a feature or prompt:
     ```bash
     git add src/ docs/
     git commit -m "feat: implement feature description"
     git push origin main
     ```
   - Other teammates pull the latest updates:
     ```bash
     git pull origin main
     ```
3. **Agent Continuity**: When a teammate opens the updated repo on their laptop, their AI assistant automatically reads `docs/APPROACH.md` and recent `docs/logs.txt` entries, immediately picking up where the team left off.

---

*Build freely. Use AI freely. Secure what you build. Document what you claim. Prove what you implemented.*

---

## MediShield implementation

The Nexas team implementation lives in `src/` and provides a working synthetic clinic workflow plus a security demonstration. See:

- `docs/GAP_ANALYSIS.md` for the starter-to-product gap analysis.
- `docs/API.md` for routes and demo accounts.
- `docs/SECURITY.md` for server-side controls and limitations.
- `docs/VERIFICATION.md` for independent verification evidence and remaining deployment gaps.
- `deployment/README.md` for local startup and deployment requirements.

Run locally:

```bash
cd src
npm run check
npm test
npm start
```

The main red-team path is: Doctor A reads Patient A's consented record, attempts Patient B's record and receives `403`, then an administrator sees the generated security event, tests the `HONEY-001` alert, and activates incident lockdown.


## MediShield — Live Zero-Trust Clinic Security Platform

The Nexas implementation extends the secure clinic prototype into a live, server-authoritative zero-trust demonstration. Patient, Doctor, and Admin/Security Operator experiences remain role-specific while sharing the same authenticated backend state.

- **Patient:** privacy center, synthetic appointments, records, consent, access history, alerts, and mobile-first navigation.
- **Doctor:** clinical appointments, consented records, access history, and live security notifications.
- **Admin:** Security Command Center, live feed, rule-based anomaly telemetry, honeytoken, BOLA simulation, containment, audit verification, and synthetic demo reset.
- **Realtime:** Socket.IO authenticates the existing session cookie and publishes minimized events to scoped user, patient, and role rooms. Sensitive record content is never broadcast.

See [`docs/REALTIME.md`](docs/REALTIME.md) for transport and LAN configuration and [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) for the exact three-device five-minute sequence. The project remains honest about its local JSON persistence, rule-based detection, tamper-evident audit chain, and undeployed HTTPS boundary.


The final hardening pass adds server-enforced time-bound consent requests, provenance trace IDs for authorized synthetic exports, session-family replay detection, real AES-256-GCM breach simulation, and an optional server-only privacy-first Gemini assistant. See `docs/ACCEPTANCE_MATRIX.md` for the exact PASS/PARTIAL/UNVERIFIED matrix; the project does not claim production readiness while persistence and network deployment remain local-prototype boundaries.
