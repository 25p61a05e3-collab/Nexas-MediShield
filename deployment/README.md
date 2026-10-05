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
| `CORS_ORIGIN` | Explicit allowed browser origin | Yes for cross-origin hosting |
| `SESSION_SECRET` | At least 32 random characters in production | Yes |
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
