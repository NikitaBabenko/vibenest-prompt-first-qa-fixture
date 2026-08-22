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

The web service listens on `PORT` and exposes `/`, `/healthz`, `/meta`, and `/topology`.
The API workspace exposes `/healthz`, `/db/ready`, and `/topology`.

Set `QA_STARTUP_MODE=crash` only in an isolated test deployment to produce the stable
`QA_FIXTURE_INTENTIONAL_CRASH` failure marker.
