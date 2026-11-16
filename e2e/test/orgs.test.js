const assert = require("node:assert/strict");
const { startServer } = require("../support/server");
const { pkcePair, shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, decodeJwt, api, redirectError } = require("../support/oauth");
const { newPage, authorize, closeBrowser, callbackURL } = require("../support/browser");

describe("organizations", function () {
  let server;
  let user;
  let client;
  let web;
  let redirectURI;
  let beta;

  before(async function () {
    this.timeout(60000);
    server = await startServer({ org: { enabled: true, enabled_domain_based_autolookup: true } });
    user = await createUser(server, { username: shortID("org"), email: "ada@acme.example" });
    redirectURI = await callbackURL();
    client = await createClient(server, {
      name: "Org app",
      redirect_uris: ["http://localhost/cb"],
      grant_types: ["password"],
      scopes: ["openid", "profile"],
    });
    web = await createClient(server, {
      name: "Org web",
      redirect_uris: [redirectURI],
      grant_types: ["authorization_code"],
      scopes: ["openid", "profile"],
    });
    const created = await api(server, "POST", "/api/orgs", { name: "Acme", slug: "acme", domains: ["acme.example"] });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const member = await api(server, "POST", `/api/orgs/${created.body.id}/members`, { user_id: user.id, role: "member" });
    assert.equal(member.status, 201, JSON.stringify(member.body));
  });

  after(async function () {
    await closeBrowser();
    if (server) {
      await server.stop();
    }
  });

  function authorizeURL(pkce) {
    const url = new URL(`${server.base}/oauth/authorize`);
    url.searchParams.set("client_id", web.id);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid profile");
    url.searchParams.set("state", shortID("st"));
    url.searchParams.set("nonce", shortID("no"));
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
    return url;
  }

  async function exchange(callback, pkce) {
    return tokenRequest(server.base, {
      grant_type: "authorization_code",
      code: callback.searchParams.get("code"),
      redirect_uri: redirectURI,
      code_verifier: pkce.verifier,
    }, { id: web.id, secret: web.secret });
  }

  async function ensureBeta() {
    if (beta) {
      return beta;
    }
    const created = await api(server, "POST", "/api/orgs", { name: "Beta", slug: "beta" });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const member = await api(server, "POST", `/api/orgs/${created.body.id}/members`, { user_id: user.id, role: "member" });
    assert.equal(member.status, 201, JSON.stringify(member.body));
    beta = created.body;
    return beta;
  }

  it("selects the organization from the email domain when autolookup is on", async function () {
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const claims = decodeJwt(issued.body.id_token);
    assert.equal(claims.org_slug, "acme");
    assert.ok(claims.org_id);
  });

  it("rejects an explicit organization when the user is not a member", async function () {
    const other = await api(server, "POST", "/api/orgs", { name: "Other", slug: "other" });
    assert.equal(other.status, 201, JSON.stringify(other.body));
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
      organization: "other",
    }, client);
    assert.equal(issued.status, 400);
    assert.equal(issued.body.error, "access_denied");
  });

  it("does not show the selector when the user belongs to one organization", async function () {
    const page = await newPage();
    const pkce = pkcePair();
    const callback = await authorize(page, authorizeURL(pkce).toString(), { ...user, org: false });
    const issued = await exchange(callback, pkce);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(decodeJwt(issued.body.id_token).org_slug, "acme");
    await page.context().close();
  });

  it("still uses domain autolookup for the password grant when the user belongs to two organizations", async function () {
    await ensureBeta();
    const issued = await tokenRequest(server.base, {
      grant_type: "password",
      username: user.username,
      password: user.password,
      scope: "openid",
    }, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(decodeJwt(issued.body.id_token).org_slug, "acme");
  });

  it("shows the selector and stamps the organization the user picks", async function () {
    await ensureBeta();
    const page = await newPage();
    const pkce = pkcePair();
    const callback = await authorize(page, authorizeURL(pkce).toString(), { ...user, org: "beta" });
    assert.equal(callback.searchParams.get("error"), null);
    const issued = await exchange(callback, pkce);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const claims = decodeJwt(issued.body.id_token);
    assert.equal(claims.org_slug, "beta");
    assert.ok(claims.org_id);
    await page.context().close();
  });

  it("skips the selector when the request already names an organization", async function () {
    await ensureBeta();
    const page = await newPage();
    const pkce = pkcePair();
    const url = authorizeURL(pkce);
    url.searchParams.set("organization", "acme");
    const callback = await authorize(page, url.toString(), { ...user, org: false });
    const issued = await exchange(callback, pkce);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(decodeJwt(issued.body.id_token).org_slug, "acme");
    await page.context().close();
  });

  it("returns interaction_required for prompt=none when a choice is required", async function () {
    await ensureBeta();
    const page = await newPage();
    const pkce = pkcePair();
    const url = authorizeURL(pkce);
    url.searchParams.set("organization", "beta");
    const callback = await authorize(page, url.toString(), { ...user, org: false });
    assert.ok(callback.searchParams.get("code"));
    const none = authorizeURL(pkcePair());
    none.searchParams.set("prompt", "none");
    const response = await page.request.get(none.toString(), { maxRedirects: 0 });
    const body = redirectError(response);
    assert.equal(body.status, 302);
    assert.equal(body.error, "interaction_required");
    await page.context().close();
  });
});
