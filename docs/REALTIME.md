# MediShield Realtime Architecture

MediShield now attaches Socket.IO to the existing Node HTTP server. The API remains the security authority; Socket.IO only distributes minimized state changes after the server has completed authorization and audit work.

## Authenticated rooms

- `user:{userId}` — the authenticated user’s private notifications.
- `patient:{patientId}` — patient-scoped record and consent activity.
- `role:admin`, `role:doctor`, `role:patient` — role-scoped operational notifications.

The handshake authenticates the existing HttpOnly `ms_session` cookie. Unauthenticated sockets are rejected. The client never supplies a role, patient identity, consent decision, severity, lockdown state, or authorization result.

## Events

The backend publishes minimized events including `appointment.created`, `appointment.updated`, `appointment.cancelled`, `consent.granted`, `consent.revoked`, `record.accessed`, `record.denied`, `security.alert`, `security.anomaly`, `honeytoken.triggered`, `session.revoked`, `incident.lockdown`, `incident.recovered`, `audit.updated`, and `demo.reset`.

Clinical summaries and notes are never broadcast. Clients fetch sensitive detail through the existing authenticated REST endpoint, which repeats resource authorization on every request.

## Three-device demo

Set `HOST=0.0.0.0` only for a controlled LAN demo and configure an explicit comma-separated `CORS_ORIGIN` for the browser origins. Start one server and connect three devices to the same server URL using separate accounts:

- Doctor laptop: Doctor A.
- Admin laptop: Admin.
- Patient phone: Patient A.

Do not use `Access-Control-Allow-Origin: *`, hardcode a LAN IP, or expose the demo server to an untrusted network.

## Deployment boundary

Socket.IO requires a long-lived process or a hosting configuration that supports WebSocket upgrades and sticky/session-compatible routing. The current prototype still uses atomic local JSON persistence; it is not horizontally scalable and does not claim MongoDB production persistence.
