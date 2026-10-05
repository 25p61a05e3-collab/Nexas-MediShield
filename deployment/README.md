# Deployment Documentation — Build Secure 24

## Overview

This directory contains deployment configuration and deployment records for your application.
Place all relevant infrastructure and deployment configuration files here.

---

## Live Deployment Reference

- **Live Application URL:** Not deployed in this local prototype
- **Hosting Platform:** Local Node.js runtime for the submitted demo
- **Access Credentials:** See `docs/API.md`; all accounts are synthetic demo identities.

---

## Required Environment Variables

Document all required environment configuration keys needed to run the application:

| Variable Name | Description | Required (Yes/No) |
|---------------|-------------|-------------------|
| `NODE_ENV` | `development` or `production`; production enables secure cookies | Yes |
| `PORT` | HTTP listen port | No |
| `HOST` | Listen address; use `0.0.0.0` only for a controlled LAN or host runtime | No |
| `CORS_ORIGIN` | Explicit allowed browser origin | Yes for cross-origin hosting |
| `SESSION_SECRET` | At least 32 random characters in production | Yes |
| `ENCRYPTION_KEY` | 64 hex characters representing a 32-byte AES-256-GCM key for the controlled breach simulation | Required for that simulation only |
| `GEMINI_API_KEY` | Optional server-side-only Gemini API key for the privacy-first assistant | No |
| `MEDISHIELD_DATA_FILE` | JSON adapter path for the prototype | No |

---

## Build & Deployment Instructions

Provide step-by-step instructions for building and launching the deployment:

1. Copy `src/.env.example` to a local `.env` and replace `SESSION_SECRET` with a random value.
2. Run `cd src && npm run check && npm test`.
3. Run `cd src && npm start`, then open `http://127.0.0.1:4100`.
4. For production, place the Node process behind HTTPS, inject environment variables through the host, replace the JSON adapter with a managed database, and restrict `CORS_ORIGIN` to the deployed frontend origin.

## Health check

`GET /api/health` returns a secret-free status object and marks that the demo dataset is synthetic.

## Prototype limitation

No public deployment URL is claimed until the team provisions hosting, HTTPS, a managed database, and production secrets. The implementation must not be presented as production-ready without those controls.

## Realtime deployment requirements

The enhanced server serves the frontend and Socket.IO endpoint from one Node process. A deployment provider must support WebSocket upgrades, long-lived processes, environment-driven `PORT` and `HOST`, and an exact `CORS_ORIGIN`. Configure the frontend and API origins consistently; do not use wildcard CORS.

The current project still persists synthetic data through the local atomic JSON adapter. Before public deployment, replace it with a managed database and migrations, inject `SESSION_SECRET` through the host, configure HTTPS, add backups and monitoring, and verify Socket.IO through the deployed origin. No Vercel, Render, MongoDB Atlas, HTTPS, or public URL is claimed as configured by this repository.
