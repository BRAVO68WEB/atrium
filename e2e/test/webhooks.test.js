const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser, managementToken } = require("../support/oauth");
const { newPage, submitLogin, closeBrowser } = require("../support/browser");
const { until } = require("../support/wait");

function listen() {
  const events = [];
  const receiver = http.createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      events.push({
        event: request.headers["x-webhook-event"],
        signature: request.headers["x-webhook-signature"],
        timestamp: request.headers["x-webhook-timestamp"],
        body: Buffer.concat(chunks).toString(),
      });
      response.writeHead(204);
      response.end();
    });
  });
  return new Promise((resolve) => {
    receiver.listen(0, "127.0.0.1", () => {
      const { port } = receiver.address();
      resolve({
        url: `http://127.0.0.1:${port}/hook`,
        events,
        close: () => new Promise((done) => receiver.close(done)),
      });
    });
  });
}

function signed(event, secret) {
  const mac = crypto.createHmac("sha256", secret).update(`${event.timestamp}.${event.body}`).digest("hex");
  return `sha256=${mac}`;
}

describe("webhooks", function () {
  const secret = "hook-secret";
  let server;
  let user;
  const receivers = [];

  before(async function () {
    this.timeout(60000);
    server = await startServer({
      security: { allow_insecure_fetch: true, fetch_allow_ips: ["127.0.0.1"] },
    });
    user = await createUser(server, { username: shortID("hook") });
  });

  after(async function () {
    await closeBrowser();
    for (const receiver of receivers) {
      await receiver.close();
    }
    if (server) {
      await server.stop();
    }
  });

  async function subscribe(events) {
    const receiver = await listen();
    receivers.push(receiver);
    const token = await managementToken(server);
    const created = await fetch(`${server.base}/api/webhooks`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: receiver.url, events, secret }),
    });
    const body = await created.json();
    assert.equal(created.status, 201, JSON.stringify(body));
    return receiver;
  }

  it("delivers login and not logout for a login subscription", async function () {
    const receiver = await subscribe(["login"]);
    const page = await newPage();
    await page.goto(`${server.base}/login`);
    await submitLogin(page, user.username, user.password);
    await page.waitForURL(/oauth\/authorize/);
    await until(() => receiver.events.some((event) => event.event === "login"));
    const delivered = receiver.events;
    assert.ok(delivered.some((event) => event.event === "login"));
    assert.equal(delivered.some((event) => event.event === "logout"), false);
    const login = delivered.find((event) => event.event === "login");
    assert.equal(login.signature, signed(login, secret));
    await page.context().close();
  });

  it("delivers logout only to a logout subscription", async function () {
    const receiver = await subscribe(["logout"]);
    const page = await newPage();
    await page.goto(`${server.base}/login`);
    await submitLogin(page, user.username, user.password);
    await page.waitForURL(/oauth\/authorize/);
    await page.goto(`${server.base}/oauth/logout`);
    await page.click("button[type=submit]");
    await page.waitForSelector("text=session has ended");
    await until(() => receiver.events.some((event) => event.event === "logout"));
    const delivered = receiver.events;
    assert.ok(delivered.some((event) => event.event === "logout"));
    assert.equal(delivered.some((event) => event.event === "login"), false);
    await page.context().close();
  });

  it("delivers login_failed for a wrong password", async function () {
    const receiver = await subscribe(["login_failed"]);
    const page = await newPage();
    await page.goto(`${server.base}/login`);
    await submitLogin(page, user.username, "wrong-password");
    await page.waitForSelector(".error");
    await until(() => receiver.events.some((event) => event.event === "login_failed"));
    const delivered = receiver.events;
    assert.ok(delivered.some((event) => event.event === "login_failed"));
    await page.context().close();
  });

  it("delivers user_registered for a management-created user", async function () {
    const receiver = await subscribe(["user_registered"]);
    const created = await createUser(server, { username: shortID("reghook") });
    await until(() => receiver.events.some((item) => item.event === "user_registered"));
    const delivered = receiver.events;
    const event = delivered.find((item) => item.event === "user_registered");
    assert.ok(event);
    assert.match(event.body, new RegExp(created.username));
  });
});
