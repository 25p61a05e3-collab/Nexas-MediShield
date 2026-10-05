# MediShield API

All `/api/*` endpoints return JSON and include an `X-Request-Id` response header. Authentication uses an HttpOnly `ms_session` cookie. Error responses have the shape `{ error: { code, message, requestId } }` and never expose stack traces, hashes, or secrets.

## Public

- `GET /api/health` — service status and synthetic-data marker; no secrets.
- `POST /api/auth/login` — email/password login with throttling and generic failure messages.
- `POST /api/auth/register` — patient registration with strong-password policy and duplicate-email protection.

## Authenticated

- `POST /api/auth/logout` — revokes the current server-side session.
- `GET /api/me` — current minimized identity, dashboard stats, and lockdown state.
- `GET /api/profile` / `PATCH /api/profile` — caller-scoped profile read and update with audit logging.
- `GET /api/dashboard` — role-specific summary.
- `GET /api/appointments` — only the caller's patient/doctor appointments, or all for admins.
- `POST /api/appointments` — patient-only booking with allowlisted date/time/doctor fields.
- `PATCH /api/appointments/:id/status` — relationship-checked status update.
- `GET /api/records` — minimized authorized record list.
- `GET /api/records/:id` — resource-level authorization, consent, honeytoken, and lockdown checks.
- `POST /api/records/:id/notes` — doctor-only, consent-checked synthetic note creation.
- `GET /api/access-history` — patient transparency feed or admin audit feed.
- `GET /api/consents` — caller-scoped consent list.
- `POST /api/consents` — patient-only grant/revoke operation.

## Admin-only

- `GET /api/users` — minimized user directory without password hashes.
- `PATCH /api/users/:id/status` — activate/deactivate a user and revoke their sessions; admin-only.
- `GET /api/security/summary` — posture metrics and recent audit events.
- `GET /api/security/events` — security events, including denied requests and honeytoken alerts.
- `POST /api/security/lockdown` — enable/disable incident containment.
- `GET /api/security/verify-audit` — verifies the tamper-evident hash chain.

## Demo identities

All data is synthetic and only for local demonstration.

| Role | Email | Password |
|---|---|---|
| Patient A | `patient.a@medishield.demo` | `DemoPatientA!2026` |
| Patient B | `patient.b@medishield.demo` | `DemoPatientB!2026` |
| Doctor A | `doctor.a@medishield.demo` | `DemoDoctorA!2026` |
| Doctor B | `doctor.b@medishield.demo` | `DemoDoctorB!2026` |
| Admin | `admin@medishield.demo` | `DemoAdmin!2026` |


## Realtime and admin demo controls

Socket.IO is served from the same origin at `/socket.io/`. The handshake requires the authenticated `ms_session` cookie. Clients receive only minimized events in scoped rooms; sensitive record detail remains REST-only.

- `POST /api/red-team/bola` — admin-only controlled BOLA simulation using the existing doctor authorization predicate; returns the actual status and records an audit/security event.
- `POST /api/red-team/honeytoken` — admin-only trigger of the real `HONEY-001` honeytoken logic.
- `POST /api/red-team/anomaly` — admin-only repeated-denial simulation using the real rule-based detector.
- `POST /api/demo/reset` — admin-only reset of synthetic state and broadcast of `demo.reset`.

All new routes require authentication, admin authorization, bounded JSON input, safe errors, and audit/security generation where applicable. No endpoint trusts a client-supplied role or security result.


## Hardening routes

- `GET /api/consent-requests` — caller-scoped pending and decided access requests.
- `POST /api/consent-requests` — doctor-only request for a patient with a scheduled relationship; validates reason and duration.
- `PATCH /api/consent-requests/:id` — patient-owner-only approval or denial; approval creates or updates a time-bound consent.
- `POST /api/records/:id/export` — authorized synthetic record export with persisted trace ID and provenance metadata.
- `GET /api/forensics?traceId=...` — admin-only provenance lookup.
- `POST /api/security/breach-simulation` — admin-only real AES-256-GCM round-trip demonstration; unavailable unless `ENCRYPTION_KEY` is configured.
- `POST /api/assistant` — authenticated, least-privilege optional Gemini assistant; rejects prompt injection/data-exfiltration questions and returns an unavailable response when `GEMINI_API_KEY` is absent.

Reused session tokens are detected before protected routes. The server revokes the token family, emits a security event, notifies the admin room, and returns `401` without exposing session details.
