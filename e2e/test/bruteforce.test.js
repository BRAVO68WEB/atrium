const assert = require("node:assert/strict");
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
        body: Buffer.concat(chunks).toString(),
      });
      response.writeHead(204);
      response.end();
    });
  });
  return new Promise((resolve) => {
    receiver.listen(0, "127.0.0.1", () => {
      resolve({
        url: `http://127.0.0.1:${receiver.address().port}/hook`,
        events,
        close: () => new Promise((done) => receiver.close(done)),
      });
    });
  });
}

describe("brute force detection", function () {
  let server;
  let receiver;
  let user;

  before(async function () {
    this.timeout(60000);
    receiver = await listen();
    server = await startServer({
      security: { allow_insecure_fetch: true, fetch_allow_ips: ["127.0.0.1"] },
    });
    user = await createUser(server, { username: shortID("brute") });
    const token = await managementToken(server);
    const created = await fetch(`${server.base}/api/webhooks`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: receiver.url,
        secret: "hook-secret",
        events: ["login_failed", "bruteforce_detected"],
      }),
    });
    assert.equal(created.status, 201, await created.text());
  });

  after(async function () {
    await closeBrowser();
    if (receiver) {
      await receiver.close();
    }
    if (server) {
      await server.stop();
    }
  });

  it("emits one bruteforce_detected event on the fifth failure and still allows the real password", async function () {
    const page = await newPage();
    await page.goto(`${server.base}/login`);
    const failed = () => receiver.events.filter((event) => event.event === "login_failed").length;
    const detected = () => receiver.events.filter((event) => event.event === "bruteforce_detected");
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      await submitLogin(page, user.username, "wrong-password");
      await page.waitForSelector(".error");
    }
    await until(() => failed() >= 4);
    assert.equal(failed(), 4);
    assert.equal(detected().length, 0);

    await submitLogin(page, user.username, "wrong-password");
    await page.waitForSelector(".error");
    await until(() => detected().length >= 1 && failed() >= 5);
    assert.equal(detected().length, 1);
    assert.ok(JSON.parse(detected()[0].body).data.failures >= 5);

    await submitLogin(page, user.username, "wrong-password");
    await page.waitForSelector(".error");
    await until(() => failed() >= 6);
    assert.equal(detected().length, 1);

    await submitLogin(page, user.username, user.password);
    await page.waitForURL(/oauth\/authorize/);
    await page.context().close();
  });
});
