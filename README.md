# VibeNest Prompt-First QA Fixture

A deliberately small public Node.js monorepo for repeatable deployment checks. The default
root command starts the web service, while the second workspace provides a PostgreSQL readiness
probe for grouped deployments.

## Requirements

- Node.js 22.13 or newer
- npm 10 or newer

## Commands

```bash
npm install
npm test
npm run check
npm start
```

The web service listens on `PORT` and exposes `/`, `/healthz`, `/meta`, `/topology`, and a
fail-closed `/protected` route. When VibeNest injects its server-only `VIBENEST_AUTH_*`
configuration, the web service enables Authorization Code flow with S256 PKCE at
`/auth/vibenest/login`, the exact `/auth/vibenest/callback`, and a CSRF-protected local logout.
OIDC tokens stay server-side, while the browser receives only an opaque, HTTP-only application
session ID. Sessions and pending login state are stored in PostgreSQL through the platform-provided
`DATABASE_URL`; no Auth value belongs in a committed `.env` file.

The API workspace exposes `/healthz`, `/db/ready`, and `/topology`.

Set `QA_STARTUP_MODE=crash` only in an isolated test deployment to produce the stable
`QA_FIXTURE_INTENTIONAL_CRASH` failure marker.
