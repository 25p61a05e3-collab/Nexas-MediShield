# Project Approach & Architecture — Build Secure 24

**Team ID:** 02A
**Project Name:** MediShield
**Team Size:** 2 Members
**Primary Track / Domain:** Secure clinic and appointment management

---

## 1. Problem Understanding, Scope & Threat Model

### 1.1 Problem Statement & Real-World Motivation
MediShield is a synthetic clinic platform that makes sensitive medical-record access visible, detectable, containable, and accountable. The security story is intentionally demonstrated through a real backend: identity is authenticated, resource access is authorized against the patient/doctor relationship, denied access is audited, honeytoken access alerts administrators, and lockdown blocks sensitive operations.

### 1.2 Target Users & Personas
- **Patient:** books appointments, sees only their own records, manages doctor consent, and reviews access transparency.
- **Doctor:** sees appointments and only authorized patient records, with every clinical access audited.
- **Admin:** manages users and appointments, investigates security events, and activates or disables incident lockdown.

### 1.3 Threat Model & Attack Surface
- **Critical assets:** credentials, opaque sessions, synthetic medical records, consent relationships, audit/security events, and lockdown state.
- **Attack vectors:** credential stuffing, BOLA/IDOR, privilege escalation, NoSQL-style operator injection, XSS, session reuse, excessive record access, and honeytoken probing.
- **Controls:** scrypt password hashing, server-side RBAC and relationship checks, strict validation, rate limits, security headers, explicit CORS, safe errors, append-only structured events, anomaly rules, and lockdown enforcement.

---

## 2. Technical Architecture & Secure System Design

### 2.1 High-Level Architecture Overview
The prototype uses a Node.js HTTP API and static browser client. Requests pass through request IDs, security headers, CORS, body-size limits, session authentication, role/resource authorization, and domain services before reaching a JSON persistence adapter. The adapter is intentionally isolated so managed database persistence can replace it later without changing the API contract.

### 2.2 Data Flow & Component Interaction
The browser sends same-origin requests with an opaque session cookie. The API authenticates the session, validates the request, checks role and resource relationship, emits an audit/security event, performs the minimum domain operation, and returns a minimized response. Medical-record reads additionally check consent, lockdown status, anomaly rules, and the honeytoken boundary.

### 2.3 Technology Stack Rationale
- **Backend / API:** Node.js built-in HTTP server keeps the starter runnable without an unverified dependency supply chain while still supporting explicit middleware boundaries.
- **Frontend / Client:** accessible semantic HTML, CSS, and browser JavaScript provide a fast, responsive role-specific console without a framework build step.
- **Persistence:** a JSON repository adapter supports a deterministic demo and is replaceable by a managed database in deployment.
- **Authentication & cryptography:** `crypto.scrypt` for password hashing and HMAC-signed, server-side opaque sessions; secrets are environment-provided.

### 2.4 Defense-in-Depth Security Controls
*Detail the specific security controls implemented:*
1. **Authentication & Session Security:** salted scrypt hashes, short-lived opaque sessions, server-side revocation, generic login errors, and login throttling.
2. **Authorization & Access Control:** role checks plus patient ownership and doctor-consent relationship checks for every sensitive resource ID.
3. **Input Validation & Sanitization:** explicit allowlists for route parameters, statuses, dates, names, notes, and query filters; no dynamic query operators.
4. **Rate Limiting & Abuse Prevention:** bounded request bodies and per-IP login/API windows with security events for repeated abuse.
5. **Secrets & Configuration Hygiene:** environment-provided session secret, no secrets in responses or logs, and `.env.example` only.

---

## 3. Implementation Milestones & 24-Hour Timeline

| Milestone / Phase | Time Window | Key Objectives & Deliverables | Security Verification | Status |
|---|---|---|---|---|
| **Phase 1: Foundation & Setup** | 0h – 4h | Contract onboarding, repository setup, JSON schemas, seed data | Baseline and secret review | `Complete` |
| **Phase 2: Core Domain & Auth** | 4h – 12h | Authentication, sessions, appointments, records, consent | Auth and authorization tests | `In progress` |
| **Phase 3: Security & Hardening**| 12h – 18h | Validation, audit, honeytoken, anomaly rules, lockdown | BOLA and containment tests | `Planned` |
| **Phase 4: Polish & Deployment**| 18h – 24h | UI, docs, production build, final verification | Full test suite and health check | `Planned` |

---

## 4. Architecture Decision Records (ADRs)

### ADR-001: Minimal dependency local prototype
- **Status:** Accepted
- **Context:** The official starter contains no package manifest or runtime and the demo must be reproducible without assuming a managed database is available.
- **Options Considered:**
  1. Add a framework and external database immediately.
  2. Use Node built-ins with an isolated JSON repository adapter.
- **Decision & Rationale:** Choose Node built-ins and an adapter to keep the prototype deterministic and reduce supply-chain and setup friction. The adapter preserves a path to MongoDB/PostgreSQL deployment.
- **Security & Performance Trade-offs:** The local JSON store is not a horizontally scaled production database; deployment documentation explicitly calls this a prototype limitation. Authorization and audit controls remain server-side.

### ADR-002: Relationship-aware authorization
- **Status:** Accepted
- **Context:** RBAC alone cannot prevent Doctor A from reading Patient B or a patient from reading another patient's record.
- **Options Considered:**
  1. Hide unauthorized resources in the frontend.
  2. Enforce role, identity, resource, consent, and lockdown checks in the API.
- **Decision & Rationale:** Enforce every resource decision in the backend and emit an access-denied security event. Frontend visibility is treated only as usability.
- **Security & Performance Trade-offs:** Extra relationship lookups are required, but they provide the demonstrable BOLA protection demanded by the project.

---

## 5. Engineering Journal & Real-Time Decision Log

*Maintain this chronological log as your team builds during the 24-hour hackathon.*

### [YYYY-MM-DD HH:MM IST] Entry 1: Project Initialization & Scope Lock
- **Focus:** Initial repository setup, team alignment, and schema architecture.
- **Key Challenges:** 
- **Resolution:** 

### [YYYY-MM-DD HH:MM IST] Entry 2: Implementation Milestone Progress
- **Focus:** Implement the synthetic clinic API, role-aware console, audit trail, honeytoken, and incident lockdown.
- **Key Challenges:** The starter had no runtime, package manifest, or persistence layer; local socket access is restricted in the execution environment.
- **Resolution:** Added a dependency-light Node HTTP API with a JSON repository adapter, static browser UI, and in-process security integration tests that exercise the real handler without making unsupported network claims.

---

## 6. Testing, Security Verification & Deployment Record

### 6.1 Testing & Security Verification Strategy
- **Unit & Integration Tests:** `src/test/security.test.js` verifies health secrecy boundaries, login/logout session invalidation, doctor consent and BOLA denial, security-event creation, honeytoken alerting, admin lockdown, malformed-input rejection, strong-password registration, caller-scoped profile updates, repeated-denial anomaly detection, patient isolation, consent revocation, origin enforcement, throttling, body limits, and tamper-evident audit verification. The suite passed 11/11 tests.
- **Static Analysis & Linting:** `npm run check` passed for `server.js` and `public/app.js`. No dependency install is required by the local prototype.

### 6.2 Deployment Verification
- **Live Deployment Platform:** Not deployed; local Node runtime is documented as a prototype limitation.
- **Deployment URL:** Intentionally blank until the team provisions HTTPS hosting and a managed database.
- **Health Check Endpoint:** `GET /api/health`, secret-free and synthetic-data marked.

### ADR-003: Server-authoritative realtime transport
- **Status:** Accepted
- **Context:** The product demo must show Patient, Doctor, and Admin clients reacting to the same security state without terminal commands or refreshes.
- **Decision:** Attach Socket.IO to the existing HTTP server. Authenticate the handshake from the existing session cookie, derive scoped rooms from the authenticated identity, and emit minimized domain/security events only after REST authorization and audit logic succeeds.
- **Security trade-off:** The current single-process transport is suitable for a controlled demo but is not a horizontally scaled event architecture. Sensitive clinical payloads remain REST-only and are never broadcast.

### ADR-004: Real backend simulations over frontend claims
- **Status:** Accepted
- **Context:** Judges need repeatable BOLA, honeytoken, anomaly, containment, audit, and reset demonstrations from the browser.
- **Decision:** Add admin-only routes that invoke existing authorization, audit, honeytoken, anomaly, lockdown, and persistence logic. The UI displays returned backend results and never increments security counters itself.

### [2026-10-05 15:43 IST] Entry 3: Live zero-trust extension
- **Focus:** Extend the secure clinic prototype into a Socket.IO-backed three-device demonstration while preserving the REST security foundation.
- **Key Challenges:** The execution device blocks local WebSocket connections, so the transport test cannot honestly be reported as a pass here.
- **Resolution:** Added authenticated Socket.IO rooms, server-authoritative event publication, live notifications, admin red-team controls, configurable LAN binding, and a regression test that passes when transport is available and skips only on the documented device restriction.

### 6.3 Realtime verification boundary
- `npm run check` passed after the realtime extension.
- `npm test` executed 13 tests: 12 passed and 1 Socket.IO transport test skipped because this device returns a local WebSocket error.
- No browser or three-device network PASS is claimed in this environment.
