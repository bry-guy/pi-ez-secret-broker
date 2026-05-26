import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { readOnePasswordConnectSecret } from "../lib/onepassword-connect.mjs";

function startMockConnect() {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push({ method: req.method, url: req.url, authorization: req.headers.authorization });
    res.setHeader("content-type", "application/json");
    if (req.url?.startsWith("/v1/vaults?")) {
      res.end(JSON.stringify([{ id: "vault-1", name: "bry-guy" }]));
      return;
    }
    if (req.url?.startsWith("/v1/vaults/vault-1/items?")) {
      res.end(JSON.stringify([{ id: "item-1", title: "GITHUB_TOKEN" }]));
      return;
    }
    if (req.url === "/v1/vaults/vault-1/items/item-1") {
      res.end(JSON.stringify({
        id: "item-1",
        title: "GITHUB_TOKEN",
        fields: [
          { id: "username", label: "username", value: "ignored" },
          { id: "credential", label: "credential", value: "ghp_secret" }
        ]
      }));
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not found" }));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, requests, url: `http://127.0.0.1:${port}` });
    });
  });
}

test("readOnePasswordConnectSecret resolves vault/item/field through Connect API", async () => {
  const previous = process.env.OP_CONNECT_TOKEN;
  process.env.OP_CONNECT_TOKEN = "connect-token";
  const mock = await startMockConnect();
  try {
    const value = await readOnePasswordConnectSecret(
      { type: "1password-connect", url: mock.url, tokenEnv: "OP_CONNECT_TOKEN" },
      { vault: "bry-guy", item: "GITHUB_TOKEN", field: "credential" }
    );
    assert.equal(value, "ghp_secret");
    assert.equal(mock.requests.length, 3);
    assert.ok(mock.requests.every((request) => request.authorization === "Bearer connect-token"));
  } finally {
    await new Promise((resolve) => mock.server.close(resolve));
    if (previous === undefined) delete process.env.OP_CONNECT_TOKEN;
    else process.env.OP_CONNECT_TOKEN = previous;
  }
});
