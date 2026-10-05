# MediShield Five-Minute Demo Guide

**Team:** Nexas (02A)<br>
**Data:** Synthetic demonstration data only

## Setup

```bash
cd src
copy .env.example .env
# For one-machine testing keep HOST=127.0.0.1 and CORS_ORIGIN=http://localhost:4100.
# For a controlled LAN demo use HOST=0.0.0.0 and set CORS_ORIGIN to the exact browser origins.
npm start
```

For three devices on the same trusted network, find the host laptop’s LAN address and open `http://LAN-IP:4100` on each device. Use separate authenticated accounts; do not use privileged role switching.

## Devices

1. **Doctor laptop:** `doctor.a@medishield.demo` / `DemoDoctorA!2026`
2. **Admin/security laptop:** `admin@medishield.demo` / `DemoAdmin!2026`
3. **Patient phone:** `patient.a@medishield.demo` / `DemoPatientA!2026`

## Five-minute sequence

1. **0:00–0:40 — authenticate:** sign in on all three devices. Each top bar identifies `DOCTOR MODE`, `ADMIN MODE`, or `PATIENT MODE`; the Alerts drawer is live.
2. **0:40–1:20 — appointment:** Patient opens Appointments and books a synthetic consultation. The doctor and admin receive `appointment.created` without refresh.
3. **1:20–2:10 — consent:** Doctor requests access through the consent workflow when available; Patient reviews the privacy/consent view and grants or revokes access. The doctor and admin receive the corresponding live event. Every record request is authorized again server-side.
4. **2:10–3:00 — authorized versus BOLA:** Doctor opens the authorized Patient A record. Admin opens Security Center → Demo / Red Team Lab → BOLA / IDOR. The real backend returns `403`, creates an audit/security event, and the live feed updates.
5. **3:00–3:40 — honeytoken and anomaly:** Admin triggers `HONEY-001`, then runs Behavioral anomaly. The backend creates the high-severity honeytoken event and rule-based anomaly telemetry; the admin feed receives both.
6. **3:40–4:30 — revoke and contain:** Patient revokes consent. Doctor’s next record request is denied. Admin activates containment; all connected clients receive `incident.lockdown` and sensitive record operations are blocked server-side.
7. **4:30–5:00 — prove and recover:** Admin verifies the tamper-evident audit chain, shows the latest security feed, then recovers the system. All devices receive `incident.recovered`. Use Reset demo only when the judge asks for a clean synthetic state.

## Honest boundaries

The demo uses a local atomic JSON store, not MongoDB. It uses rule-based anomaly detection, not machine learning. Audit logs are tamper-evident, not tamper-proof. HTTPS, managed persistence, backups, monitoring, and production WebSocket routing must be configured and verified separately before any production claim.


## Hardening add-on sequence

After the core live flow, Doctor opens Consent & access requests, selects Patient A, enters a reason and duration, and submits a request. Patient approves or denies from the phone without a browser prompt. Doctor can export an authorized synthetic record to obtain a trace ID; Admin can look up that trace ID in the Security Center. Admin can run the encrypted database-compromise simulation when `ENCRYPTION_KEY` is configured, then use the privacy-first assistant for a navigation or security question. To demonstrate replay detection, log out and reuse an old cookie only in a controlled test environment; the server denies it and alerts Admin.
