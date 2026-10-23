const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const { compactDecrypt, exportJWK, generateKeyPair } = require("jose");
const { startServer } = require("../support/server");
const { createUser, createClient, tokenRequest } = require("../support/oauth");
const { shortID } = require("../support/pkce");
const { newPage, submitLogin, closeBrowser } = require("../support/browser");
const { dpopProof } = require("../support/dpop");

describe("push authenticator enrollment", function () {
  let server;
  let user;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ push: { enabled: true } });
    user = await createUser(server, { username: shortID("push"), password: "correct-horse" });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("shows a registration token in the fragment after sign-in", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/push/enroll`);
    if (page.url().includes("/login")) {
      await submitLogin(page, user.username, user.password);
      await page.waitForURL((current) => new URL(current).pathname === "/push/enroll", { timeout: 20000 });
    }
    const token = (await page.locator("#registration-token").innerText()).trim();
    assert.equal(token.split(".").length, 3);
    const shown = await page.locator("#enroll-url").innerText();
    assert.match(shown, /\/push\/enroll#/);
    assert.equal(await page.locator("#enroll-qr").count(), 1);
    await page.context().close();
  });

  it("approves a sign-in on the registered device", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/push/enroll`);
    if (page.url().includes("/login")) {
      await submitLogin(page, user.username, user.password);
      await page.waitForURL((current) => new URL(current).pathname === "/push/enroll", { timeout: 20000 });
    }
    const registrationToken = (await page.locator("#registration-token").innerText()).trim();
    const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });
    const registered = await fetch(`${server.base}/push/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        registration_token: registrationToken,
        public_key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
        interaction_types: ["boolean", "number_choose", "input_manual"],
        platform: "browser",
      }),
    });
    assert.equal(registered.status, 201, await registered.text());

    const client = await createClient(server, {
      name: "Shop",
      grant_types: ["urn:openid:params:grant-type:ciba"],
      scopes: ["openid"],
    });
    const started = await fetch(`${server.base}/oauth/bc-authorize`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
      },
      body: new URLSearchParams({
        login_hint: user.username,
        scope: "openid",
        binding_message: "42",
      }),
    });
    const pending = await started.json();
    assert.equal(started.status, 200, JSON.stringify(pending));
    assert.ok(pending.auth_req_id);

    await page.goto(`${server.base}/push/approve`);
    await page.locator("button[value=approve]").click();
    await page.locator("#push-approved").waitFor({ timeout: 20000 });

    const issued = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: pending.auth_req_id,
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.access_token);
    await page.context().close();
  });

  it("approves number_choose only for the shown number", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/push/enroll`);
    if (page.url().includes("/login")) {
      await submitLogin(page, user.username, user.password);
      await page.waitForURL((current) => new URL(current).pathname === "/push/enroll", { timeout: 20000 });
    }
    const registrationToken = (await page.locator("#registration-token").innerText()).trim();
    const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });
    const registered = await fetch(`${server.base}/push/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        registration_token: registrationToken,
        public_key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
        interaction_types: ["boolean", "number_choose", "input_manual"],
        platform: "browser",
      }),
    });
    assert.equal(registered.status, 201, await registered.text());

    const client = await createClient(server, {
      name: "Counter",
      grant_types: ["urn:openid:params:grant-type:ciba"],
      scopes: ["openid"],
    });
    const started = await fetch(`${server.base}/oauth/bc-authorize`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
      },
      body: new URLSearchParams({
        login_hint: user.username,
        scope: "openid",
        interaction_type: "number_choose",
        binding_message: "42",
      }),
    });
    const pending = await started.json();
    assert.equal(started.status, 200, JSON.stringify(pending));
    assert.equal(pending.binding_message, "42");

    await page.goto(`${server.base}/push/approve`);
    assert.equal(await page.locator("#binding-message").count(), 0);
    await page.locator("button[name=proof][value='42']").click();
    await page.locator("#push-approved").waitFor({ timeout: 20000 });
    const issued = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: pending.auth_req_id,
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.access_token);
    await page.context().close();
  });

  it("rejects a wrong code and then accepts the typed code", async function () {
    const page = await openEnroll(server, user);
    const key = await deviceKey();
    const registered = await registerDevice(server.base, await registrationToken(page), key.jwk);
    assert.equal(registered.status, 201, registered.text);
    const client = await cibaClient(server, "Typed");
    const pending = await backchannel(server, client, user.username, {
      interaction_type: "input_manual",
      binding_message: "abcd",
    });
    await page.goto(`${server.base}/push/approve`);
    await page.locator("#push-proof").fill("nope");
    const [rejected] = await Promise.all([
      page.waitForResponse((res) => res.url().includes("/push/approve") && res.request().method() === "POST"),
      page.locator("button[value=approve]").click(),
    ]);
    assert.equal(rejected.status(), 400);
    assert.match(await rejected.text(), /confirmation does not match/);
    const early = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: pending.auth_req_id,
    }, client);
    assert.notEqual(early.status, 200);

    await page.goto(`${server.base}/push/approve`);
    await page.locator("#push-proof").fill("abcd");
    await page.locator("button[value=approve]").click();
    await page.locator("#push-approved").waitFor({ timeout: 20000 });
    const issued = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: pending.auth_req_id,
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.access_token);
    await page.context().close();
  });

  it("denies the sign-in from the approve page", async function () {
    const page = await openEnroll(server, user);
    await registerDevice(server.base, await registrationToken(page), (await deviceKey()).jwk);
    const client = await cibaClient(server, "Deny");
    const pending = await backchannel(server, client, user.username, { binding_message: "42" });
    await page.goto(`${server.base}/push/approve`);
    await page.locator("button[value=deny]").click();
    await page.waitForSelector("text=Nothing is waiting");
    const issued = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: pending.auth_req_id,
    }, client);
    assert.equal(issued.body.error, "access_denied");
    await page.context().close();
  });

  it("rejects a number that was not offered", async function () {
    const page = await openEnroll(server, user);
    await registerDevice(server.base, await registrationToken(page), (await deviceKey()).jwk);
    const client = await cibaClient(server, "Wrong number");
    const pending = await backchannel(server, client, user.username, {
      interaction_type: "number_choose",
      binding_message: "42",
    });
    await page.goto(`${server.base}/push/approve`);
    const buttons = page.locator("button[name=proof]");
    const count = await buttons.count();
    let wrong = "";
    for (let i = 0; i < count; i += 1) {
      const value = await buttons.nth(i).getAttribute("value");
      if (value !== "42") {
        wrong = value;
        break;
      }
    }
    assert.notEqual(wrong, "");
    await page.locator(`button[name=proof][value="${wrong}"]`).click();
    await page.waitForSelector("text=confirmation does not match");
    const issued = await tokenRequest(server.base, {
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: pending.auth_req_id,
    }, client);
    assert.equal(issued.body.error, "authorization_pending");
    await page.context().close();
  });

  it("rejects an interaction type the device did not register", async function () {
    const solo = await createUser(server, { username: shortID("limited"), password: "correct-horse" });
    const page = await openEnroll(server, solo);
    await registerDevice(server.base, await registrationToken(page), (await deviceKey()).jwk, "", ["boolean"]);
    const client = await cibaClient(server, "Limited");
    const started = await fetch(`${server.base}/oauth/bc-authorize`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
      },
      body: new URLSearchParams({
        login_hint: solo.username,
        scope: "openid",
        interaction_type: "input_manual",
        binding_message: "abcd",
      }),
    });
    const body = await started.json();
    assert.equal(started.status, 400, JSON.stringify(body));
    assert.match(body.error_description, /does not support the interaction type/);
    await page.context().close();
  });

  it("rejects a different DPoP key and a reused nonce", async function () {
    const solo = await createUser(server, { username: shortID("dpop"), password: "correct-horse" });
    const page = await openEnroll(server, solo);
    const key = await deviceKey();
    const registered = await registerDevice(server.base, await registrationToken(page), key.jwk, "", ["boolean"]);
    const listed = await deviceFetch(server.base, key, "GET", `/push/pending?device_id=${registered.device_id}`, registered.device_credential);
    assert.equal(listed.status, 200, listed.text);
    const other = await deviceKey();
    const mismatched = await deviceFetch(server.base, other, "GET", `/push/pending?device_id=${registered.device_id}`, registered.device_credential, listed.nonce);
    assert.equal(mismatched.status, 401);
    const again = await deviceFetch(server.base, key, "GET", `/push/pending?device_id=${registered.device_id}`, registered.device_credential, listed.nonce);
    assert.equal(again.status, 400, again.text);
    assert.match(again.text, /nonce_replayed/);
    await page.context().close();
  });

  it("revokes the device and advertises poll only", async function () {
    const discovered = await fetch(`${server.base}/.well-known/oauth-push-notification`);
    const doc = await discovered.json();
    assert.deepEqual(doc.delivery_modes_supported, ["poll"]);
    assert.equal(doc.push_relay_endpoint, undefined);
    const solo = await createUser(server, { username: shortID("revoked"), password: "correct-horse" });
    const page = await openEnroll(server, solo);
    const key = await deviceKey();
    const registered = await registerDevice(server.base, await registrationToken(page), key.jwk, "", ["boolean"]);
    const revoked = await deviceFetch(server.base, key, "POST", "/push/revoke", registered.device_credential, "", {
      "content-type": "application/x-www-form-urlencoded",
    }, `device_id=${encodeURIComponent(registered.device_id)}`);
    assert.equal(revoked.status, 204, revoked.text);
    const client = await cibaClient(server, "Revoked");
    const started = await fetch(`${server.base}/oauth/bc-authorize`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
      },
      body: new URLSearchParams({ login_hint: solo.username, scope: "openid" }),
    });
    const body = await started.json();
    assert.equal(started.status, 400, JSON.stringify(body));
    assert.equal(body.error, "device_revoked");
    await page.context().close();
  });
});

describe("push device HTTP", function () {
  after(async function () {
    await closeBrowser();
  });

  it("polls the device and records a ping", async function () {
    this.timeout(60000);
    const sink = await listen();
    const server = await startServer({
      push: { enabled: true, ping_enabled: true },
      security: { allow_insecure_fetch: true, fetch_allow_ips: ["127.0.0.1"] },
    });
    try {
      const discovered = await fetch(`${server.base}/.well-known/oauth-push-notification`);
      const doc = await discovered.json();
      assert.deepEqual(doc.delivery_modes_supported, ["ping", "poll"]);
      const user = await createUser(server, { username: shortID("ping"), password: "correct-horse" });
      const key = await deviceKey();
      const page = await openEnroll(server, user);
      const registered = await registerDevice(server.base, await registrationToken(page), key.jwk, sink.url);
      assert.equal(registered.status, 201, registered.text);
      const client = await cibaClient(server, "Ping");
      const pending = await backchannel(server, client, user.username, { binding_message: "42" });
      assert.equal(sink.events.length, 1);
      const wake = JSON.parse(sink.events[0].body);
      assert.deepEqual(wake, { wake_reason: "auth_request", ref_id: pending.auth_req_id });
      const listed = await deviceFetch(server.base, key, "GET", `/push/pending?device_id=${registered.device_id}`, registered.device_credential);
      assert.equal(listed.status, 200);
      assert.equal(listed.body.pending[0].AuthReqID, pending.auth_req_id);
      const decided = await deviceFetch(server.base, key, "POST", "/push/pending", registered.device_credential, listed.nonce, {
        "content-type": "application/json",
      }, JSON.stringify({
        device_id: registered.device_id,
        auth_req_id: pending.auth_req_id,
        action: "approve",
      }));
      assert.equal(decided.status, 204, decided.text);
      const issued = await tokenRequest(server.base, {
        grant_type: "urn:openid:params:grant-type:ciba",
        auth_req_id: pending.auth_req_id,
      }, client);
      assert.equal(issued.status, 200, JSON.stringify(issued.body));
      assert.ok(issued.body.access_token);
      await page.context().close();
    } finally {
      await server.stop();
      await sink.close();
    }
  });

  it("returns a sealed pull and plaintext on the next poll", async function () {
    this.timeout(60000);
    const sink = await listen();
    const server = await startServer({
      push: { enabled: true, push_enabled: true },
      security: { allow_insecure_fetch: true, fetch_allow_ips: ["127.0.0.1"] },
    });
    try {
      const discovered = await fetch(`${server.base}/.well-known/oauth-push-notification`);
      const doc = await discovered.json();
      assert.deepEqual(doc.delivery_modes_supported, ["push", "poll"]);
      assert.equal(doc.push_relay_endpoint, undefined);
      const user = await createUser(server, { username: shortID("seal"), password: "correct-horse" });
      const key = await deviceKey();
      const page = await openEnroll(server, user);
      const registered = await registerDevice(server.base, await registrationToken(page), key.jwk, sink.url);
      const client = await cibaClient(server, "Seal");
      const pending = await backchannel(server, client, user.username, { binding_message: "42" });
      const sealed = await deviceFetch(server.base, key, "GET", `/push/pending?device_id=${registered.device_id}`, registered.device_credential, "", {
        accept: "application/jose",
      });
      assert.equal(sealed.status, 200, sealed.text);
      assert.match(sealed.type, /application\/jose/);
      const decrypted = await compactDecrypt(sealed.text, key.privateKey);
      assert.match(new TextDecoder().decode(decrypted.plaintext), new RegExp(pending.auth_req_id));
      const open = await deviceFetch(server.base, key, "GET", `/push/pending?device_id=${registered.device_id}`, registered.device_credential, sealed.nonce);
      assert.equal(open.status, 200, open.text);
      assert.match(open.type, /application\/json/);
      assert.equal(open.body.pending[0].AuthReqID, pending.auth_req_id);
      await page.context().close();
    } finally {
      await server.stop();
      await sink.close();
    }
  });

  it("sends the push wake to the relay", async function () {
    this.timeout(60000);
    const relay = await listen();
    const device = await listen();
    const server = await startServer({
      push: { enabled: true, push_enabled: true, ping_enabled: true, relay_endpoint: relay.url },
      security: { allow_insecure_fetch: true, fetch_allow_ips: ["127.0.0.1"] },
    });
    try {
      const discovered = await fetch(`${server.base}/.well-known/oauth-push-notification`);
      const doc = await discovered.json();
      assert.deepEqual(doc.delivery_modes_supported, ["push", "ping", "poll"]);
      assert.equal(doc.push_relay_endpoint, relay.url);
      const user = await createUser(server, { username: shortID("relay"), password: "correct-horse" });
      const key = await deviceKey();
      const page = await openEnroll(server, user);
      const registered = await registerDevice(server.base, await registrationToken(page), key.jwk, device.url);
      assert.equal(registered.status, 201, registered.text);
      const client = await cibaClient(server, "Relay");
      const pending = await backchannel(server, client, user.username, { binding_message: "42" });
      assert.equal(device.events.length, 0);
      assert.equal(relay.events.length, 1);
      const wake = JSON.parse(relay.events[0].body);
      assert.equal(wake.wake_reason, "auth_request");
      assert.equal(wake.ref_id, pending.auth_req_id);
      assert.equal(wake.push_address, device.url);
      await page.context().close();
    } finally {
      await server.stop();
      await relay.close();
      await device.close();
    }
  });
});

async function openEnroll(server, user) {
  const page = await newPage();
  await page.goto(`${server.base}/push/enroll`);
  if (page.url().includes("/login")) {
    await submitLogin(page, user.username, user.password);
    await page.waitForURL((current) => new URL(current).pathname === "/push/enroll", { timeout: 20000 });
  }
  return page;
}

async function registrationToken(page) {
  return (await page.locator("#registration-token").innerText()).trim();
}

async function deviceKey() {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const exported = await exportJWK(publicKey);
  return {
    privateKey,
    jwk: { kty: exported.kty, crv: exported.crv, x: exported.x, y: exported.y },
  };
}

async function registerDevice(base, token, jwk, pushAddress, types) {
  const response = await fetch(`${base}/push/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      registration_token: token,
      public_key: jwk,
      interaction_types: types || ["boolean", "number_choose", "input_manual"],
      platform: "browser",
      push_address: pushAddress || "",
    }),
  });
  const text = await response.text();
  return { status: response.status, text, ...JSON.parse(text) };
}

async function cibaClient(server, name) {
  return createClient(server, {
    name,
    grant_types: ["urn:openid:params:grant-type:ciba"],
    scopes: ["openid"],
  });
}

async function backchannel(server, client, username, extra) {
  const started = await fetch(`${server.base}/oauth/bc-authorize`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
    },
    body: new URLSearchParams({
      login_hint: username,
      scope: "openid",
      ...extra,
    }),
  });
  const pending = await started.json();
  assert.equal(started.status, 200, JSON.stringify(pending));
  return pending;
}

async function deviceFetch(base, key, method, path, credential, nonce, headers, body) {
  const url = `${base}${path}`;
  const proof = await dpopProof(method, url, "", { key, ath: false });
  const response = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${credential}`,
      dpop: proof,
      ...(nonce ? { "replay-nonce": nonce } : {}),
      ...(headers || {}),
    },
    body,
  });
  const text = await response.text();
  const type = response.headers.get("content-type") || "";
  let parsed = text;
  if (type.includes("json") && text) {
    parsed = JSON.parse(text);
  }
  return { status: response.status, body: parsed, text, type, nonce: response.headers.get("replay-nonce") };
}

function listen() {
  const events = [];
  const receiver = http.createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      events.push({ body: Buffer.concat(chunks).toString() });
      response.writeHead(204);
      response.end();
    });
  });
  return new Promise((resolve) => {
    receiver.listen(0, "127.0.0.1", () => {
      const { port } = receiver.address();
      resolve({
        url: `http://127.0.0.1:${port}/wake`,
        events,
        close: () => new Promise((done) => receiver.close(done)),
      });
    });
  });
}
