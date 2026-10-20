const crypto = require("node:crypto");
const { SignJWT, exportJWK, generateKeyPair } = require("jose");

async function dpopProof(method, url, accessToken, opts) {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(publicKey);
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
      jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    })
    .setIssuedAt()
    .sign(privateKey);
}

module.exports = { dpopProof };
