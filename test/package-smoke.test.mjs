import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

test("package is installable as a pi extension package", () => {
  assert.equal(packageJson.name, "pi-ez-secret-broker");
  assert.equal(packageJson.version, "0.2.0");
  assert.ok(packageJson.keywords.includes("pi-package"));
  assert.deepEqual(packageJson.pi.extensions, ["./extensions"]);
  assert.ok(packageJson.peerDependencies["@earendil-works/pi-coding-agent"]);
});

test("README documents bootstrap command and non-persistence posture", async () => {
  const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
  assert.match(readme, /\/secret-broker init/);
  assert.match(readme, /avoid writing plaintext secrets/i);
  assert.match(readme, /1Password Connect/i);
});
