const assert = require("node:assert/strict");
const http = require("node:http");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const {
  createUser, createClient, tokenRequest, introspect, revoke, userInfo, decodeJwt, readBody, redirectError,
} = require("../support/oauth");
const { newPage, authorize, closeBrowser, submitLogin, waitForCallback, callbackURL } = require("../support/browser");

describe("standard OAuth flows", function () {
  let server;
  let user;
  let web;
  let publicClient;
  let service;
  let passwordApp;
  let deviceApp;
  let parApp;
  let implicitApp;
  let redirectURI;

  before(async function () {
    this.timeout(60000);
    server = await startServer();
    user = await createUser(server, { username: shortID("flow") });
    redirectURI = await callbackURL();
    const redirect = [redirectURI];
    web = await createClient(server, {
      name: "Web",
      redirect_uris: redirect,
      grant_types: ["authorization_code", "refresh_token"],
      scopes: ["openid", "profile", "email"],
    });
    publicClient = await createClient(server, {
      name: "Public",
      redirect_uris: redirect,
      grant_types: ["authorization_code", "refresh_token"],
      scopes: ["openid", "profile"],
      token_endpoint_auth_method: "none",
    });
    service = await createClient(server, {
      name: "Service",
      grant_types: ["client_credentials"],
      scopes: ["openid"],
    });
    passwordApp = await createClient(server, {
      name: "Password",
      grant_types: ["password", "refresh_token"],
      scopes: ["openid", "profile"],
    });
    deviceApp = await createClient(server, {
      name: "Device",
      grant_types: ["urn:ietf:params:oauth:grant-type:device_code"],
      scopes: ["openid", "profile"],
    });
    parApp = await createClient(server, {
      name: "PAR",
      redirect_uris: redirect,
      grant_types: ["authorization_code", "refresh_token"],
      scopes: ["openid", "profile"],
    });
    implicitApp = await createClient(server, {
      name: "Implicit",
      redirect_uris: redirect,
      grant_types: ["implicit", "authorization_code"],
      scopes: ["openid", "profile"],
    });
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  it("publishes discovery and JWKS", async function () {
    const discovery = await readBody(await fetch(`${server.base}/.well-known/openid-configuration`));
    assert.equal(discovery.status, 200);
    assert.equal(discovery.body.issuer, server.base);
    assert.match(discovery.body.authorization_endpoint, /\/oauth\/authorize$/);
    assert.match(discovery.body.token_endpoint, /\/oauth\/token$/);
    assert.match(discovery.body.jwks_uri, /\/oidc\/jwks$/);
    assert.match(discovery.body.revocation_endpoint, /\/oauth\/revoke$/);
    assert.match(discovery.body.introspection_endpoint, /\/oauth\/introspect$/);
    assert.match(discovery.body.pushed_authorization_request_endpoint, /\/oauth\/par$/);
    assert.match(discovery.body.device_authorization_endpoint, /\/oauth\/device$/);
    assert.match(discovery.body.registration_endpoint, /\/oauth\/register$/);
    assert.match(discovery.body.userinfo_endpoint, /\/oidc\/userinfo$/);
    assert.deepEqual(discovery.body.backchannel_token_delivery_modes_supported, ["poll"]);
    const jwks = await readBody(await fetch(`${server.base}/oidc/jwks`));
    assert.equal(jwks.status, 200);
    assert.ok(jwks.body.keys.some((key) => key.alg === "RS256" && key.kid));
  });

  it("issues a client-credentials token that is not a JWT", async function () {
    const issued = await tokenRequest(server.base, {
      grant_type: "client_credentials",
      scope: "openid",
    }, { id: service.id, secret: service.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(issued.body.token_type, "Bearer");
    assert.equal(issued.body.access_token.includes("."), false);
  });

  it("completes authorization code, PKCE, UserInfo, refresh, introspect, and revoke", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const state = "state-1";
    const nonce = "nonce-1";
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid profile");
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const callback = await authorize(page, url.toString(), user);
    assert.equal(callback.searchParams.get("state"), state);
    const code = callback.searchParams.get("code");
    assert.ok(code);

    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: web.id, secret: web.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(decodeJwt(issued.body.id_token).sub, user.id);
    assert.equal(decodeJwt(issued.body.id_token).nonce, nonce);

    const info = await userInfo(server.base, issued.body.access_token);
    assert.equal(info.status, 200, JSON.stringify(info.body));
    assert.equal(info.body.sub, user.id);

    const quiet = pkcePair();
    const again = new URL(`${server.base}/oauth/authorize`);
    again.searchParams.set("client_id", web.id);
    again.searchParams.set("redirect_uri", redirectURI);
    again.searchParams.set("response_type", "code");
    again.searchParams.set("scope", "openid profile");
    again.searchParams.set("prompt", "none");
    again.searchParams.set("code_challenge", quiet.challenge);
    again.searchParams.set("code_challenge_method", quiet.method);
    await page.goto(again.toString());
    const silent = await waitForCallback(page);
    assert.ok(silent.searchParams.get("code"));
    assert.equal(await page.locator("#username").count(), 0);

    const refreshed = await tokenRequest(server.base, {
      grant_type: "refresh_token",
      refresh_token: issued.body.refresh_token,
    }, { id: web.id, secret: web.secret });
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
    assert.notEqual(refreshed.body.refresh_token, issued.body.refresh_token);

    const active = await introspect(server.base, web, refreshed.body.access_token);
    assert.equal(active.body.active, true);
    assert.equal(active.body.sub, user.id);
    assert.equal(active.body.iss, server.base);
    assert.equal(typeof active.body.iat, "number");
    assert.ok(active.body.iat <= active.body.exp);
    const revoked = await revoke(server.base, web, refreshed.body.access_token);
    assert.equal(revoked.status, 200);
    const inactive = await introspect(server.base, web, refreshed.body.access_token);
    assert.equal(inactive.body.active, false);
    await page.context().close();
  });

  it("returns access_denied when consent is denied", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", publicClient.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid profile");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const callback = await authorize(page, url.toString(), { ...user, consent: "deny" });
    assert.equal(callback.searchParams.get("error"), "access_denied");
    await page.context().close();
  });

  it("lets a public client exchange a code without a secret", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", publicClient.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("prompt", "consent");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const callback = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: publicClient.id });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.access_token);
    await page.context().close();
  });

  it("issues a password grant", async function () {
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid profile",
    }, { id: passwordApp.id, secret: passwordApp.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.ok(issued.body.refresh_token);
    assert.equal(issued.body.access_token.includes("."), false);
  });

  it("approves a device code in the browser", async function () {
    const device = await readBody(await fetch(`${server.base}/oauth/device`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${deviceApp.id}:${deviceApp.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ scope: "openid profile" }),
    }));
    assert.equal(device.status, 200, JSON.stringify(device.body));
    const page = await newPage();
    await page.goto(`${server.base}/login`);
    await submitLogin(page, user.username, user.password);
    await page.waitForURL(/oauth\/authorize/);
    await page.goto(`${server.base}/device?user_code=${encodeURIComponent(device.body.user_code)}`);
    await page.click("button[value=approve]");
    await page.waitForSelector("text=authorized");
    const issued = await tokenRequest(server.base, {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: device.body.device_code,
    }, { id: deviceApp.id, secret: deviceApp.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    await page.context().close();
  });

  it("uses a pushed authorization request", async function () {
    const pkce = pkcePair();
    const pushed = await readBody(await fetch(`${server.base}/oauth/par`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${parApp.id}:${parApp.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        response_type: "code",
        redirect_uri: redirectURI,
        scope: "openid profile",
        code_challenge: pkce.challenge,
        code_challenge_method: pkce.method,
      }),
    }));
    assert.equal(pushed.status, 201, JSON.stringify(pushed.body));
    const page = await newPage();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", parApp.id);
    url.searchParams.set("request_uri", pushed.body.request_uri);
    const callback = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: parApp.id, secret: parApp.secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    await page.context().close();
  });

  it("ends the browser session on logout", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    await authorize(page, url.toString(), user);
    await page.goto(`${server.base}/oauth/logout`);
    await page.click("button[type=submit]");
    await page.waitForSelector("text=session has ended");
    const next = pkcePair();
    const again = new URL(`${server.base}/oauth/authorize`);
    again.searchParams.set("client_id", web.id);
    again.searchParams.set("redirect_uri", redirectURI);
    again.searchParams.set("response_type", "code");
    again.searchParams.set("scope", "openid");
    again.searchParams.set("code_challenge", next.challenge);
    again.searchParams.set("code_challenge_method", next.method);
    await page.goto(again.toString());
    await page.waitForSelector("#username");
    await page.context().close();
  });

  it("registers a client dynamically and uses its secret", async function () {
    const registered = await readBody(await fetch(`${server.base}/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "Dynamic",
        redirect_uris: [redirectURI],
        grant_types: ["client_credentials"],
        scope: "openid",
      }),
    }));
    assert.equal(registered.status, 201, JSON.stringify(registered.body));
    const issued = await tokenRequest(server.base, {
      grant_type: "client_credentials",
      scope: "openid",
    }, { id: registered.body.client_id, secret: registered.body.client_secret });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
  });

  it("rejects an unregistered redirect", async function () {
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", "https://evil.example/cb");
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    const response = await fetch(url, { redirect: "manual" });
    const body = await response.json();
    assert.equal(response.status, 400);
    assert.equal(body.error, "invalid_request");
    assert.equal(response.headers.get("location"), null);
  });

  it("rejects a reused code and a wrong verifier", async function () {
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const page = await newPage();
    const callback = await authorize(page, url.toString(), user);
    const code = callback.searchParams.get("code");
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, web);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const again = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, web);
    assert.equal(again.body.error, "invalid_grant");

    const other = pkcePair();
    url.searchParams.set("code_challenge", other.challenge);
    const second = await authorize(page, url.toString(), user);
    const wrong = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: second.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, web);
    assert.equal(wrong.body.error, "invalid_grant");
    await page.context().close();
  });

  it("returns login_required when prompt=none has no session", async function () {
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("prompt", "none");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const response = await fetch(url, { redirect: "manual" });
    const body = redirectError(response);
    assert.equal(body.status, 302);
    assert.equal(body.error, "login_required");
    assert.doesNotMatch(JSON.stringify(body), /<form/);
  });

  it("returns implicit and hybrid tokens in the fragment", async function () {
    const page = await newPage();
    const tokenURL = new URL(`${server.base}/oauth/authorize`);
    tokenURL.searchParams.set("client_id", implicitApp.id);
    tokenURL.searchParams.set("redirect_uri", redirectURI);
    tokenURL.searchParams.set("response_type", "token");
    tokenURL.searchParams.set("scope", "openid");
    tokenURL.searchParams.set("state", "implicit-state");
    const tokenCallback = await authorize(page, tokenURL.toString(), user);
    const tokenFragment = new URLSearchParams(tokenCallback.hash.slice(1));
    assert.ok(tokenFragment.get("access_token"));
    assert.equal(tokenFragment.get("state"), "implicit-state");
    assert.equal(tokenCallback.search, "");

    const hybrid = pkcePair();
    const hybridURL = new URL(`${server.base}/oauth/authorize`);
    hybridURL.searchParams.set("client_id", implicitApp.id);
    hybridURL.searchParams.set("redirect_uri", redirectURI);
    hybridURL.searchParams.set("response_type", "code id_token");
    hybridURL.searchParams.set("scope", "openid");
    hybridURL.searchParams.set("nonce", "hybrid-nonce");
    hybridURL.searchParams.set("state", "hybrid-state");
    hybridURL.searchParams.set("code_challenge", hybrid.challenge);
    hybridURL.searchParams.set("code_challenge_method", hybrid.method);
    const hybridCallback = await authorize(page, hybridURL.toString(), user);
    const hybridFragment = new URLSearchParams(hybridCallback.hash.slice(1));
    assert.ok(hybridFragment.get("code"));
    assert.equal(decodeJwt(hybridFragment.get("id_token")).nonce, "hybrid-nonce");
    assert.equal(hybridCallback.search, "");
    await page.context().close();
  });

  it("rejects the implicit response type for a code client", async function () {
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "token");
    url.searchParams.set("scope", "openid");
    const response = await fetch(url, { redirect: "manual" });
    const body = redirectError(response);
    assert.equal(body.status, 302);
    assert.equal(body.error, "unauthorized_client");
  });

  it("posts the code when response_mode is form_post", async function () {
    const sink = await postedCallback();
    const client = await createClient(server, {
      name: "Form post",
      redirect_uris: [sink.url],
      grant_types: ["authorization_code"],
      scopes: ["openid"],
    });
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("redirect_uri", sink.url);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("response_mode", "form_post");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("state", "form-state");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const page = await newPage();
    await authorize(page, url.toString(), user);
    assert.equal(sink.hits.length, 1);
    assert.equal(sink.hits[0].method, "POST");
    assert.equal(sink.hits[0].url, "/cb");
    const posted = new URLSearchParams(sink.hits[0].body);
    assert.ok(posted.get("code"));
    assert.equal(posted.get("state"), "form-state");
    await sink.close();
    await page.context().close();
  });

  it("keeps the code challenge stored by PAR", async function () {
    const inside = pkcePair();
    const outside = pkcePair();
    const pushed = await readBody(await fetch(`${server.base}/oauth/par`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${parApp.id}:${parApp.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        response_type: "code",
        redirect_uri: redirectURI,
        scope: "openid",
        code_challenge: inside.challenge,
        code_challenge_method: inside.method,
      }),
    }));
    assert.equal(pushed.status, 201, JSON.stringify(pushed.body));
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", parApp.id);
    url.searchParams.set("request_uri", pushed.body.request_uri);
    url.searchParams.set("code_challenge", outside.challenge);
    url.searchParams.set("code_challenge_method", "S256");
    const page = await newPage();
    const callback = await authorize(page, url.toString(), user);
    const rejected = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: outside.verifier,
    }, parApp);
    assert.equal(rejected.body.error, "invalid_grant");
    const again = await readBody(await fetch(`${server.base}/oauth/par`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${parApp.id}:${parApp.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        response_type: "code",
        redirect_uri: redirectURI,
        scope: "openid",
        code_challenge: inside.challenge,
        code_challenge_method: inside.method,
      }),
    }));
    url.searchParams.set("request_uri", again.body.request_uri);
    const second = await authorize(page, url.toString(), user);
    const issued = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: second.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: inside.verifier,
    }, parApp);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    await page.context().close();
  });

  it("rejects a bad password, an unknown user, and a scope the client lacks", async function () {
    const wrong = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: "not-the-password",
    }, passwordApp);
    assert.equal(wrong.body.error, "invalid_grant");
    assert.match(wrong.body.error_description, /Invalid username or password/);
    const missing = await tokenRequest(server.base, {
      grant_type: "password",
      username: "nobody-no-such-user",
      password: user.password,
    }, passwordApp);
    assert.equal(missing.body.error, "invalid_grant");
    assert.match(missing.body.error_description, /Invalid username or password/);
    const scope = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid not-a-scope",
    }, passwordApp);
    assert.equal(scope.status, 400);
    assert.equal(scope.body.error, "invalid_scope");
  });

  it("rejects a bad client secret and a scope the service lacks", async function () {
    const wrong = await tokenRequest(server.base, {
      grant_type: "client_credentials",
      scope: "openid",
    }, { id: service.id, secret: "wrong-secret" });
    assert.equal(wrong.status, 401);
    assert.equal(wrong.body.error, "invalid_client");
    const scope = await tokenRequest(server.base, {
      grant_type: "client_credentials",
      scope: "openid not-a-scope",
    }, service);
    assert.equal(scope.status, 400);
    assert.equal(scope.body.error, "invalid_scope");
  });

  it("reads and updates the signed-in user at /api/me", async function () {
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
    }, passwordApp);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const me = await readBody(await fetch(`${server.base}/api/me`, {
      headers: { Authorization: `Bearer ${issued.body.access_token}` },
    }));
    assert.equal(me.status, 200, JSON.stringify(me.body));
    assert.equal(me.body.username, user.username);
    const patched = await readBody(await fetch(`${server.base}/api/me`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${issued.body.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email: `${user.username}-next@example.com` }),
    }));
    assert.equal(patched.status, 200, JSON.stringify(patched.body));
    assert.equal(patched.body.email, `${user.username}-next@example.com`);
    const serviceToken = await tokenRequest(server.base, {
      grant_type: "client_credentials",
      scope: "openid",
    }, service);
    const denied = await readBody(await fetch(`${server.base}/api/me`, {
      headers: { Authorization: `Bearer ${serviceToken.body.access_token}` },
    }));
    assert.equal(denied.status, 403);
  });

  it("denies a device code and rejects a code that was not issued", async function () {
    const device = await readBody(await fetch(`${server.base}/oauth/device`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${deviceApp.id}:${deviceApp.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ scope: "openid" }),
    }));
    assert.equal(device.status, 200, JSON.stringify(device.body));
    const early = await tokenRequest(server.base, {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: device.body.device_code,
    }, deviceApp);
    assert.equal(early.body.error, "authorization_pending");
    const blocked = await readBody(await fetch(`${server.base}/oauth/device`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${deviceApp.id}:${deviceApp.secret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ scope: "openid not-a-scope" }),
    }));
    assert.equal(blocked.body.error, "invalid_scope");
    const page = await newPage();
    await page.goto(`${server.base}/login`);
    await submitLogin(page, user.username, user.password);
    await page.waitForURL(/oauth\/authorize/);
    await page.goto(`${server.base}/device`);
    await page.fill("#user_code", "ZZZZ-ZZZZ");
    await page.click("button[type=submit]");
    await page.waitForSelector("text=invalid or has expired");
    await page.goto(`${server.base}/device?user_code=${encodeURIComponent(device.body.user_code)}`);
    await page.click("button[value=deny]");
    await page.waitForSelector("text=Request denied");
    const issued = await tokenRequest(server.base, {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: device.body.device_code,
    }, deviceApp);
    assert.equal(issued.body.error, "access_denied");
    await page.context().close();
  });

  it("keeps the browser session when the hint belongs to another client", async function () {
    const pkce = pkcePair();
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid");
    url.searchParams.set("nonce", "logout-nonce");
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    const page = await newPage();
    const callback = await authorize(page, url.toString(), user);
    const browserToken = await tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, web);
    const other = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
    }, passwordApp);
    await page.goto(`${server.base}/oauth/logout?id_token_hint=${encodeURIComponent(other.body.id_token)}`);
    const still = new URL(`${server.base}/oauth/authorize`);
    still.searchParams.set("client_id", web.id);
    still.searchParams.set("redirect_uri", redirectURI);
    still.searchParams.set("response_type", "code");
    still.searchParams.set("scope", "openid");
    still.searchParams.set("code_challenge", pkcePair().challenge);
    still.searchParams.set("code_challenge_method", "S256");
    await page.goto(still.toString());
    assert.equal(page.url().includes("/login"), false);
    await page.goto(`${server.base}/oauth/logout?id_token_hint=${encodeURIComponent(browserToken.body.id_token)}`);
    await page.goto(still.toString());
    await page.waitForSelector("#username");
    await page.context().close();
  });
});

function postedCallback() {
  const hits = [];
  const receiver = http.createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      hits.push({
        method: request.method,
        url: request.url,
        body: Buffer.concat(chunks).toString(),
      });
      response.writeHead(200, { "content-type": "text/html" });
      response.end("<h1>callback</h1>");
    });
  });
  return new Promise((resolve) => {
    receiver.listen(0, "127.0.0.1", () => {
      const { port } = receiver.address();
      resolve({
        url: `http://localhost:${port}/cb`,
        hits,
        close: () => new Promise((done) => receiver.close(done)),
      });
    });
  });
}
