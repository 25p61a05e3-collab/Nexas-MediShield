# MediShield Acceptance Matrix

**Verification date:** 2026-10-05<br>
**Latest implementation commit:** recorded in `docs/logs.txt` after this hardening pass

| Area | Status | Evidence / boundary |
|---|---|---|
| Patient registration, login, logout, throttling | PASS | Existing and expanded Node security tests |
| Doctor authentication and role enforcement | PASS | Existing authentication and resource tests |
| Patient profile isolation | PASS | Existing profile isolation test |
| Appointment booking and status workflow | PASS | Existing route and authorization coverage; UI now uses an inline form |
| Synthetic records and clinical notes | PASS | Server-side resource authorization and synthetic-only seed |
| Doctor workflow | PARTIAL | Appointment, records, history, consent-request UI; broader patient queue polish remains |
| Admin Security Command Center | PASS | Live metrics, feed, containment, audit, Red Team controls |
| BOLA / IDOR and RBAC | PASS | Existing tests plus real admin BOLA simulation |
| Input validation, safe errors, headers, CORS, rate limiting | PASS | Existing regression suite |
| Malicious file defense | N/A | No upload feature exists; no upload surface is exposed |
| Honeytoken | PASS | Real HONEY-001 backend event and live notification path |
| Rule-based behavioral anomaly | PASS | Repeated-denial detector, backend simulation, live anomaly event |
| Time-bound patient consent | PASS | Doctor request, patient approval/denial, expiry metadata, revocation enforcement test |
| Incident lockdown | PASS | Server-enforced 423 behavior and live containment/recovery |
| Red Team Lab | PASS | BOLA, honeytoken, anomaly, reset controls call backend logic |
| Forensic provenance | PASS | Authorized export, trace ID persistence, admin lookup, regression test |
| Session replay detection | PASS | Revoked-session reuse revokes family, audits, and denies request |
| Privacy-first Gemini assistant | PARTIAL | Server-only optional integration and prompt-injection guard; missing-key fallback tested; external Gemini call not tested here |
| Tamper-evident audit | PASS | Hash-chain verification and controlled tamper test |
| AES-256-GCM breach simulation | PASS | Real encrypt/decrypt round trip with configured test key |
| Socket.IO | PASS | Authenticated admin rooms received server-authoritative honeytoken security alerts in the regression test; three-device LAN proof remains unverified |
| Three-device browser proof | UNVERIFIED | Requires a permitted LAN or deployed WSS-capable environment |
| Production deployment | NOT CLAIMED | Local JSON persistence, HTTPS, managed database, backups, and monitoring remain deployment work |

## Exact test results

- `npm run check`: passed.
- `npm test`: 16 tests executed; 16 passed, 0 failed, and 0 skipped, including the authenticated Socket.IO security-alert delivery test.
- Browser smoke testing was attempted but local navigation was blocked by the same device-level localhost policy.
