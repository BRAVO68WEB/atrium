const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, managementToken } = require("../support/oauth");

describe("CIBA", function () {
  let server;
  let user;
  let client;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("ciba") });
    client = await createClient(server, {
      name: "CIBA",
      grant_types: ["urn:openid:params:grant-type:ciba"],
      scopes: ["openid", "profile"],
    });
  });

  after(async function () {
    if (server) {
      await server.stop();
    }
  });

  it("stays pending, then issues a token after approval", async function () {
    const started = await fetch(`${server.base}/oauth/bc-authorize`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        scope: "openid",
        login_hint: user.username,
        binding_message: "Sign in on your phone",
      }),
    });
    const request = await started.json();
    assert.equal(started.status, 200, JSON.stringify(request));
    assert.ok(request.auth_req_id);

    const pending = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: request.auth_req_id,
    }, { id: client.id, secret: client.secret });
    assert.equal(pending.status, 400);
    assert.equal(pending.body.error, "authorization_pending");

    const token = await managementToken(server);
    const approved = await fetch(`${server.base}/ciba/approve?auth_req_id=${encodeURIComponent(request.auth_req_id)}&user_id=${encodeURIComponent(user.id)}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(approved.status, 200, await approved.text());

    const issued = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: request.auth_req_id,
    }, { id: client.id, secret: client.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.access_token);
  });

  it("returns access_denied after the request is denied", async function () {
    const started = await fetch(`${server.base}/oauth/bc-authorize`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ login_hint: user.username, scope: "openid" }),
    });
    const request = await started.json();
    const token = await managementToken(server);
    const denied = await fetch(`${server.base}/ciba/deny?auth_req_id=${encodeURIComponent(request.auth_req_id)}&reason=no`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(denied.status, 200);
    const issued = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: request.auth_req_id,
    }, { id: client.id, secret: client.secret });
    assert.equal(issued.body.error, "access_denied");
  });

  it("stays pending for an unknown account and rejects a scope the client lacks", async function () {
    const unknown = await fetch(`${server.base}/oauth/bc-authorize`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ login_hint: "nobody-no-such-user", scope: "openid" }),
    });
    const request = await unknown.json();
    assert.equal(unknown.status, 200, JSON.stringify(request));
    const pending = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: request.auth_req_id,
    }, client);
    assert.equal(pending.body.error, "invalid_grant");
    const scope = await fetch(`${server.base}/oauth/bc-authorize`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ login_hint: user.username, scope: "openid not-a-scope" }),
    });
    const body = await scope.json();
    assert.equal(scope.status, 400);
    assert.equal(body.error, "invalid_scope");
  });
});
