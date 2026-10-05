# MediShield Gap Analysis

**Project:** MediShield  
**Team:** Nexas (02A)  
**Baseline:** Official Build Secure 24 starter repository  
**Analysis date:** 2026-10-05

## 1. Baseline inspection

The supplied starter repository is an official documentation-and-metadata scaffold. It contains:

- `AGENTS.md`, `CLAUDE.md`, `README.md`, and `PARTICIPANT_RULES.md`
- `docs/APPROACH.md` and an append-only `docs/logs.txt`
- submission and team metadata under `metadata/`
- deployment guidance under `deployment/`
- an empty `src/` directory containing only `.gitkeep`
- no package manifest, application runtime, API routes, frontend, database models, tests, or deployment configuration

The starter instructions and official documentation are preserved. The application will be authored inside `src/` as required.

## 2. Required capability gaps

| Area | Starter state | MediShield target | Planned completion |
|---|---|---|---|
| Runtime | No runtime or package manifest | Node.js application with a small dependency footprint | `src/package.json`, server entrypoint |
| UI | No frontend | Responsive role-based clinic/security console | Static frontend under `src/public/` |
| Authentication | Missing | Password hashing, login throttling, signed sessions, logout/revocation | Auth service and routes |
| Authorization | Missing | RBAC plus resource-level patient/doctor relationship checks | Authorization middleware/services |
| Clinic workflow | Missing | Profiles, appointments, synthetic records, consent | Domain routes and persistence |
| Auditability | Missing | Structured audit/security events and patient access history | Append-only event store and routes |
| Detection | Missing | Honeytoken, rule-based anomaly detection, denied-request tracking | Security monitoring service |
| Containment | Missing | Admin incident lockdown that blocks sensitive operations | Lockdown state and enforcement middleware |
| Validation | Missing | Strict allowlisted body/query/route validation | Validation helpers |
| API hardening | Missing | Security headers, explicit CORS, request limits, safe errors, rate limits | HTTP middleware |
| Testing | Missing | Unit/integration/security tests for BOLA and containment | Node test suite |
| Deployment | Documentation only | Health endpoint, environment example, startup/build instructions | `src/.env.example`, deployment docs |

## 3. Security risks to address

1. **Broken object-level authorization (BOLA/IDOR):** every patient, appointment, and record identifier must be checked against the authenticated actor and current relationship.
2. **Sensitive-data disclosure:** medical records are synthetic, minimized, and never returned to unauthorized callers; audit logs contain metadata rather than clinical payloads.
3. **Credential attacks:** passwords are hashed with Node's built-in `scrypt`, login attempts are throttled, and generic authentication errors avoid account enumeration.
4. **Session compromise:** sessions are short-lived, stored server-side, revocable, and represented to clients only by opaque signed cookies.
5. **Injection/XSS:** request bodies use explicit schemas and allowlists; the browser UI renders user-controlled values with `textContent` rather than HTML interpolation.
6. **Privilege escalation:** role checks are enforced in the backend and never rely on hidden frontend navigation.
7. **Insider misuse:** every record access, denied access, consent change, administrative action, lockdown event, and honeytoken trigger is recorded.
8. **Incident response:** lockdown is persisted, audited, visible to all roles, and blocks sensitive record operations while preserving audit writes.

## 4. Deliberate prototype boundaries

- Persistence uses a local JSON store so the prototype runs without requiring a pre-provisioned external database. The store is isolated behind a repository module so it can be replaced by MongoDB or PostgreSQL without changing route contracts.
- All clinical content is synthetic demo data and is labeled as such.
- Anomaly detection is transparent rule-based detection, not machine learning.
- AI is not included because it is not required for the core security story.
- Production deployment still requires HTTPS, a managed database, secret injection, and a process supervisor; these are documented as deployment requirements rather than falsely claimed as active in the local prototype.

## 5. Implementation order

1. Runtime, configuration, JSON repository, seed data, and health endpoint.
2. Authentication, sessions, rate limiting, and role middleware.
3. Appointment and profile workflows.
4. Resource-level record authorization, consent, audit trail, and access transparency.
5. Honeytoken, anomaly rules, admin security center, and incident lockdown.
6. Frontend role dashboards and red-team demonstration flow.
7. Automated tests, documentation, and production-readiness checks.

## 6. Acceptance evidence

The implementation is complete only when automated tests demonstrate:

- Patient isolation and doctor relationship isolation.
- Admin-only security operations.
- A denied record request returning `403` and producing a security event.
- Honeytoken access producing a high-severity alert.
- Lockdown blocking sensitive record access while audit logging remains available.
- Login throttling, validation, safe errors, and session revocation.

## 7. Independent verification update

The implementation was independently inspected and retested after the baseline handoff. Syntax checks passed and the security suite was expanded to 11 passing tests covering origin enforcement, login throttling, malformed JSON, body limits, patient isolation, consent revocation, and controlled tamper-evident audit verification. An external localhost health probe was attempted but was blocked by the execution device; no external network coverage is claimed.

The remaining concrete gaps are deployment and infrastructure boundaries: the prototype uses an atomic JSON adapter rather than a managed database, has no database indexes or migration layer, is not publicly deployed, and does not implement authenticated encryption for clinical fields. These limitations remain explicitly documented and are not represented as completed security controls.
