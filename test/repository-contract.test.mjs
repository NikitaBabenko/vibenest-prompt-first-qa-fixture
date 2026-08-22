import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");

test("root selects the web workspace and declares two services", async () => {
  const rootPackage = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  assert.deepEqual(rootPackage.workspaces, ["apps/*"]);
  assert.equal(rootPackage.scripts.start, "npm --workspace @vibenest-qa/web start");

  const workspaces = await readdir(path.join(root, "apps"), { withFileTypes: true });
  assert.deepEqual(
    workspaces.filter(entry => entry.isDirectory()).map(entry => entry.name).sort(),
    ["api", "web"]
  );
});

test("Auth-only integration has no container recipe, payment artifacts, or credentials", async () => {
  const files = await collectFiles(root);
  assert.equal(files.some(file => path.basename(file).toLowerCase() === "dockerfile"), false);

  const evidencePath = path.join(root, ".vibenest", "evidence", "vibenest-auth.json");
  assert.deepEqual(JSON.parse(await readFile(evidencePath, "utf8")), {
    schemaVersion: "vibenest-auth-evidence-v1",
    framework: "node-express",
    authorizationCodePkce: true,
    serverSideCallbackValidation: true,
    httpOnlyServerSession: true,
    logout: true,
    protectedRouteTests: true
  });
  assert.equal(files.some(file => file.replaceAll("\\", "/").endsWith("/.vibenest/payments.yaml")), false);

  const inspected = files.filter(file =>
    file.endsWith("package.json")
    || file.endsWith(".mjs") && !file.endsWith("repository-contract.test.mjs")
  );
  const forbidden = [
    ["VIBENEST", "PROJECT", "PAYMENTS"].join("_"),
    [".vibenest", "payments.yaml"].join("/"),
    ["vn", "pi_"].join(""),
    ["vn", "pa_"].join(""),
    ["vn", "pr_"].join("")
  ];

  for (const file of inspected) {
    const content = await readFile(file, "utf8");
    for (const marker of forbidden) assert.equal(content.includes(marker), false, `${file} contains ${marker}`);
  }
});

async function collectFiles(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await collectFiles(fullPath));
    else output.push(fullPath);
  }
  return output;
}
