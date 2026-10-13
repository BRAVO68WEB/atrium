const http = require("node:http");
const { chromium } = require("playwright");
const { TOTP, Secret } = require("otpauth");

let browser;
let callbackServer;
let callbackPromise;

// Chromium does not pause http://localhost navigations for page.route, so a
// redirect to port 80 fails in CI where nothing is listening. Serve /cb on an
// ephemeral port and force localhost onto 127.0.0.1.
function callbackURL() {
  if (!callbackPromise) {
    callbackPromise = new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end("<h1>callback</h1>");
      });
      callbackServer = server;
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => {
        resolve(`http://localhost:${server.address().port}/cb`);
      });
    });
  }
  return callbackPromise;
}

function isCallback(current) {
  let parsed;
  try {
    parsed = new URL(current);
  } catch {
    return false;
  }
  if (parsed.pathname === "/e2e-callback") {
    return true;
  }
  return parsed.hostname === "localhost" && (parsed.pathname === "/cb" || parsed.pathname === "/cb/");
}

function isStep(current) {
  if (isCallback(current)) {
    return true;
  }
  let parsed;
  try {
    parsed = new URL(current);
  } catch {
    return false;
  }
  return parsed.pathname === "/consent" || parsed.pathname === "/mfa/enroll" || parsed.pathname === "/organization";
}

async function ensureBrowser() {
  if (!browser) {
    const headed = process.env.HEADED === "1" || process.env.HEADLESS === "false";
    browser = await chromium.launch({
      headless: !headed,
      args: ["--host-resolver-rules=MAP localhost 127.0.0.1"],
    });
  }
  return browser;
}

async function closeBrowser() {
  if (browser) {
    await browser.close();
    browser = null;
  }
  if (callbackServer) {
    const server = callbackServer;
    callbackServer = null;
    callbackPromise = null;
    await new Promise((resolve) => server.close(resolve));
  }
}

async function newPage() {
  const instance = await ensureBrowser();
  const context = await instance.newContext();
  const page = await context.newPage();
  page.on("response", (response) => {
    if (!response.headers()["set-cookie"]) {
      return;
    }
    page.context().cookies().then((cookies) => {
      if (cookies.some((cookie) => cookie.name === "session_id")) {
        page._oauthCookies = cookies;
      }
    }).catch(() => {});
  });
  return page;
}

async function submitLogin(page, username, password) {
  await page.fill("#username", username);
  await page.fill("#password", password);
  await page.click("button[type=submit]");
}

async function submitEnrollment(page) {
  await page.waitForURL((current) => {
    try {
      return new URL(current).pathname === "/mfa/enroll";
    } catch {
      return false;
    }
  }, { timeout: 15000 });
  const secret = (await page.locator(".secret-box").textContent()).trim();
  const code = new TOTP({
    secret: Secret.fromBase32(secret),
    digits: 6,
    period: 30,
    algorithm: "SHA1",
  }).generate();
  await page.fill("#code", code);
  await page.click("button[type=submit]");
}

async function failDump(page, err) {
  const text = await page.locator("body").innerText().catch(() => "");
  throw new Error(`${err.message}\nURL ${page.url()}\n${text.slice(0, 800)}`);
}

async function waitForStep(page) {
  try {
    await page.waitForURL(isStep, { timeout: 20000 });
  } catch (err) {
    await failDump(page, err);
  }
}

async function waitForCallback(page) {
  if (isCallback(page.url())) {
    return new URL(page.url());
  }
  try {
    await page.waitForURL(isCallback, { timeout: 20000 });
  } catch (err) {
    await failDump(page, err);
  }
  return new URL(page.url());
}

async function restoreSessionCookies(page) {
  if (!Array.isArray(page._oauthCookies) || page._oauthCookies.length === 0) {
    return;
  }
  await page.context().addCookies(page._oauthCookies);
}

async function authorize(page, url, options) {
  await page.goto(url);
  if (page.url().includes("/login")) {
    await submitLogin(page, options.username, options.password);
    await waitForStep(page);
  }
  if (page.url().includes("/mfa/enroll") || options.enroll) {
    await submitEnrollment(page);
    await waitForStep(page);
  }
  if (page.url().includes("/organization")) {
    if (options && options.org === false) {
      throw new Error(`organization selector was not expected\nURL ${page.url()}`);
    }
    if (options && options.org) {
      await page.locator(`input[name="organization"][value="${options.org}"]`).check();
    } else {
      await page.locator('input[name="organization"]').first().check();
    }
    await Promise.all([
      page.waitForURL((current) => !String(current).includes("/organization"), { timeout: 20000 }),
      page.locator("button[type=submit]").click(),
    ]);
    await waitForStep(page);
  }
  if (options.consent !== false && page.url().includes("/consent")) {
    if (typeof options.onConsent === "function") {
      await options.onConsent(page);
    }
    page._oauthCookies = await page.context().cookies();
    const decision = options.consent || "approve";
    try {
      await Promise.all([
        page.waitForURL(isCallback, { timeout: 20000 }),
        page.locator(`button[value="${decision}"]`).click(),
      ]);
    } catch (err) {
      await failDump(page, err);
    }
  }
  const callback = await waitForCallback(page);
  await restoreSessionCookies(page);
  return callback;
}

module.exports = {
  ensureBrowser,
  closeBrowser,
  newPage,
  submitLogin,
  authorize,
  waitForCallback,
  callbackURL,
};
