import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { APP_MARKER, createWebApp } from "../src/app.mjs";
import { CRASH_MARKER } from "../src/server.mjs";

test("root and health endpoints expose stable public markers", async () => {
  await withServer(createWebApp({}), async origin => {
    const root = await fetch(`${origin}/`);
    assert.equal(root.status, 200);
    assert.match(root.headers.get("content-type"), /^text\/html/);
    assert.match(await root.text(), new RegExp(APP_MARKER));

    const health = await fetch(`${origin}/healthz`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: "ok", service: "web" });
  });
});

test("metadata and topology reveal availability but never configuration values", async () => {
  const secretLookingValue = "do-not-reflect-this-value";
  const configuration = {
    SOURCE_COMMIT: secretLookingValue,
    API_URL: `https://${secretLookingValue}.invalid`,
    API_INTERNAL_URL: `http://${secretLookingValue}.internal`
  };

  await withServer(createWebApp(configuration), async origin => {
    const metaText = await (await fetch(`${origin}/meta`)).text();
    assert.doesNotMatch(metaText, new RegExp(secretLookingValue));
    const meta = JSON.parse(metaText);
    assert.equal(meta.service, "web");
    assert.equal(meta.sourceCommitAvailable, true);
    assert.equal(typeof meta.uptimeSeconds, "number");

    const topologyText = await (await fetch(`${origin}/topology`)).text();
    assert.doesNotMatch(topologyText, new RegExp(secretLookingValue));
    assert.deepEqual(JSON.parse(topologyText), {
      service: "web",
      apiPublicUrlAvailable: true,
      apiInternalUrlAvailable: true
    });
  });
});

test("protected and unknown routes fail closed", async () => {
  await withServer(createWebApp({}), async origin => {
    assert.equal((await fetch(`${origin}/protected`)).status, 401);
    assert.equal((await fetch(`${origin}/missing`)).status, 404);
  });
});

test("crash mode exits with a stable marker", async () => {
  const serverPath = fileURLToPath(new URL("../src/server.mjs", import.meta.url));
  const child = spawn(process.execPath, [serverPath], {
    env: { ...process.env, QA_STARTUP_MODE: "crash" },
    stdio: ["ignore", "ignore", "pipe"]
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", chunk => { stderr += chunk; });
  const [exitCode] = await once(child, "exit");

  assert.equal(exitCode, 42);
  assert.equal(stderr.trim(), CRASH_MARKER);
});

async function withServer(app, work) {
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  try {
    await work(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}
