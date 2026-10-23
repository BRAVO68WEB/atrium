const crypto = require("node:crypto");
const { SignJWT, exportJWK, generateKeyPair } = require("jose");

async function dpopKey() {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(publicKey);
  return {
    privateKey,
    jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
  };
}

async function dpopProof(method, url, accessToken, opts) {
  const key = (opts && opts.key) || (await dpopKey());
  const claims = {
    htm: method,
    htu: url,
    jti: crypto.randomBytes(16).toString("base64url"),
  };
  if (accessToken && !(opts && opts.ath === false)) {
    claims.ath = crypto.createHash("sha256").update(accessToken).digest("base64url");
  }
  return new SignJWT(claims)
    .setProtectedHeader({
      typ: "dpop+jwt",
      alg: "ES256",
      jwk: key.jwk,
    })
    .setIssuedAt()
    .sign(key.privateKey);
}

module.exports = { dpopKey, dpopProof };
