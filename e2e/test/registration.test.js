const assert = require("node:assert/strict");
const net = require("node:net");
const { startServer } = require("../support/server");
const { shortID } = require("../support/pkce");
const { createUser, createClient, tokenRequest, readBody } = require("../support/oauth");
const { newPage, submitLogin, closeBrowser } = require("../support/browser");

function startSMTP() {
  const messages = [];
  const receiver = net.createServer((socket) => {
    socket.write("220 localhost ESMTP\r\n");
    let buf = "";
    let collecting = false;
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      if (collecting) {
        const end = buf.indexOf("\r\n.\r\n");
        if (end === -1) {
          return;
        }
        messages.push(buf.slice(0, end));
        buf = buf.slice(end + 5);
        collecting = false;
        socket.write("250 queued\r\n");
      }
      const lines = buf.split("\r\n");
      buf = lines.pop();
      for (const line of lines) {
        const cmd = line.toUpperCase();
        if (cmd.startsWith("EHLO") || cmd.startsWith("HELO")) {
          socket.write("250-localhost\r\n250 OK\r\n");
        } else if (cmd === "DATA") {
          collecting = true;
          socket.write("354 send\r\n");
        } else if (cmd === "QUIT") {
          socket.write("221 bye\r\n");
          socket.end();
        } else {
          socket.write("250 ok\r\n");
        }
      }
    });
  });
  return new Promise((resolve) => {
    receiver.listen(0, "127.0.0.1", () => {
      resolve({
        port: receiver.address().port,
        messages,
        close: () => new Promise((done) => receiver.close(done)),
      });
    });
  });
}

describe("registration modes", function () {
  after(async function () {
    await closeBrowser();
  });

  it("blocks web signup and still lets management create a user", async function () {
    const server = await startServer({ security: { disable_registration: true } });
    try {
      const pageResponse = await fetch(`${server.base}/register`);
      assert.equal(pageResponse.status, 403);
      assert.match(await pageResponse.text(), /Registration is disabled/);
      const post = await fetch(`${server.base}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ username: "nobody", password: "correct-horse" }),
      });
      assert.equal(post.status, 403);

      const user = await createUser(server, { username: shortID("closed") });
      const page = await newPage();
      await page.goto(`${server.base}/login`);
      await submitLogin(page, user.username, user.password);
      await page.waitForURL(/oauth\/authorize/);
      await page.context().close();
    } finally {
      await server.stop();
    }
  });

  it("blocks dynamic client registration and still lets a management app get a token", async function () {
    const server = await startServer({ registration: { dcr_enabled: false } });
    try {
      const registered = await readBody(await fetch(`${server.base}/oauth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Blocked",
          redirect_uris: ["http://localhost/cb"],
          grant_types: ["client_credentials"],
        }),
      }));
      assert.equal(registered.status, 403);
      assert.equal(registered.body.error, "registration_disabled");

      const client = await createClient(server, {
        name: "Still allowed",
        grant_types: ["client_credentials"],
        scopes: ["openid"],
      });
      const issued = await tokenRequest(server.base, {
        grant_type: "client_credentials",
        scope: "openid",
      }, { id: client.id, secret: client.secret });
      assert.equal(issued.status, 200, JSON.stringify(issued.body));
    } finally {
      await server.stop();
    }
  });

  it("creates an account, confirms the email, and rejects a duplicate username", async function () {
    const smtp = await startSMTP();
    const server = await startServer({ smtp: { port: smtp.port } });
    try {
      const name = shortID("open");
      const page = await newPage();
      await page.goto(`${server.base}/register`);
      await page.fill("#username", name);
      await page.fill("#email", `${name}@example.com`);
      await page.fill("#password", "correct-horse");
      await page.click("button[type=submit]");
      await page.waitForURL(/\/login/);
      const deadline = Date.now() + 5000;
      while (smtp.messages.length === 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      assert.equal(smtp.messages.length > 0, true, "verification mail did not arrive");
      const link = smtp.messages.join("\n").match(/https?:\/\/\S+\/verify-email\?token=\S+/);
      assert.ok(link, smtp.messages.join("\n"));
      const verifyURL = link[0].replace(/[>\s].*$/, "");
      await page.goto(verifyURL);
      await page.waitForSelector("text=email is confirmed");
      await page.goto(verifyURL);
      await page.waitForSelector("text=invalid or has already been used");
      await page.goto(`${server.base}/login?next=/profile`);
      await submitLogin(page, name, "correct-horse");
      await page.waitForSelector("text=Your account");
      await page.goto(`${server.base}/register`);
      await page.fill("#username", name);
      await page.fill("#email", `${name}-2@example.com`);
      await page.fill("#password", "correct-horse");
      await page.click("button[type=submit]");
      await page.waitForSelector("text=username already exists");
      await page.context().close();
    } finally {
      await server.stop();
      await smtp.close();
    }
  });
});
