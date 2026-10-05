# MediShield Security Architecture

## Defense in depth

- **Authentication:** passwords are stored only as salted Node `scrypt` hashes. Login errors are generic and failed attempts are audited and throttled.
- **Sessions:** clients receive an HttpOnly, SameSite opaque cookie. Session records are server-side, short-lived, signed, and revoked on logout.
- **Authorization:** backend routes enforce role checks plus resource ownership, doctor consent, active status, and current lockdown state. Frontend hiding is not used as a security control.
- **Validation:** IDs, dates, status values, emails, names, note text, and request bodies use explicit allowlists and bounded sizes. Arbitrary query operators are never accepted.
- **API hardening:** CSP, frame denial, MIME sniffing protection, referrer policy, explicit CORS, body limits, request IDs, generic errors, and login rate limiting are enabled.
- **Cross-site request protection:** the cookie is HttpOnly/SameSite and API requests with an `Origin` header must match the configured `CORS_ORIGIN`. A production deployment should add CSRF tokens if cross-site workflows are introduced.
- **Audit:** audit events contain actor, role, action, resource, timestamp, result, reason, severity, request ID, and a previous-hash link. Passwords, tokens, and clinical payloads are not logged.
- **Transparency:** patients can review record-access and blocked-attempt history. Admins can investigate the full security event stream.
- **Honeytoken:** `HONEY-001` is a controlled synthetic decoy. Access creates a high-severity `HONEYTOKEN_TRIGGER` event and is never exposed through normal record listings.
- **Detection:** monitoring is transparent rule-based telemetry: failed logins, denied access, repeated denied access anomalies, suspicious honeytoken access, and lockdown events are visible to administrators. It is not represented as machine learning.
- **Containment:** admin lockdown persists in the store, is audited, and blocks sensitive record operations for non-admin users while leaving audit logging available.

## BOLA demonstration

Doctor A can access `record-a` because an active consent links Doctor A to Patient A. The same doctor requesting `record-b` receives `403 FORBIDDEN`, regardless of whether the resource ID is guessed, and the backend records `ACCESS_DENIED`. Patient B cannot use Patient A's record ID because patient ownership is checked server-side.

## Synthetic data and limitations

This is a prototype with synthetic records only. Local persistence is a JSON adapter for deterministic demos; production deployment must use a managed database, HTTPS, secret injection, backups, access logging, and a process supervisor. The JSON adapter is not horizontally scalable and is not a claim of production-grade database durability.

Authenticated encryption of medical fields is **not implemented** in this prototype; no encryption key or encryption claim is made. Audit records are hash-chained and the integrity endpoint has been tested against a controlled persisted-record modification, so the demonstrated property is **tamper-evident**, not tamper-proof.
