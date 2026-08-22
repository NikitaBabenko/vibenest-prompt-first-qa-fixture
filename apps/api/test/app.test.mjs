import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import { createApiApp } from "../src/app.mjs";

test("health stays available when no database is configured", async () => {
  const app = createApiApp({});
  await withServer(app, async origin => {
    assert.deepEqual(await (await fetch(`${origin}/healthz`)).json(), { status: "ok", service: "api" });
    const readiness = await fetch(`${origin}/db/ready`);
    assert.equal(readiness.status, 503);
    assert.deepEqual(await readiness.json(), { status: "unavailable", database: "postgres" });
  });
});

test("database readiness executes the bounded PostgreSQL probe", async () => {
  const calls = [];
  const pool = {
    async query(sql) {
      calls.push(sql);
      return { rows: [{ ready: 1 }] };
    },
    async end() {}
  };
  const app = createApiApp({}, { pool });

  await withServer(app, async origin => {
    const readiness = await fetch(`${origin}/db/ready`);
    assert.equal(readiness.status, 200);
    assert.deepEqual(await readiness.json(), { status: "ok", database: "postgres" });
  });
  assert.deepEqual(calls, ["SELECT 1 AS ready"]);
});

test("database failures are reduced to a stable unavailable response", async () => {
  const pool = {
    async query() { throw new Error("sensitive database detail"); },
    async end() {}
  };
  const app = createApiApp({}, { pool });

  await withServer(app, async origin => {
    const readiness = await fetch(`${origin}/db/ready`);
    const body = await readiness.text();
    assert.equal(readiness.status, 503);
    assert.doesNotMatch(body, /sensitive database detail/);
  });
});

test("topology returns booleans without reflecting URL values", async () => {
  const marker = "private-topology-marker";
  const app = createApiApp({
    WEB_URL: `https://${marker}.invalid`,
    WEB_INTERNAL_URL: `http://${marker}.internal`
  });

  await withServer(app, async origin => {
    const body = await (await fetch(`${origin}/topology`)).text();
    assert.doesNotMatch(body, new RegExp(marker));
    assert.deepEqual(JSON.parse(body), {
      service: "api",
      webPublicUrlAvailable: true,
      webInternalUrlAvailable: true
    });
    assert.equal((await fetch(`${origin}/missing`)).status, 404);
  });
});

async function withServer(app, work) {
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  try {
    await work(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await app.locals.closeResources();
  }
}
