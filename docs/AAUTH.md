# AAuth

AAuth is a separate protocol from the OAuth endpoints on this server.
`requested_actor` is unchanged. Nothing here is mounted unless
`aauth.enabled` is true. Configuration is in [Configuration](CONFIG.md).

This process can play four roles. Each role has an issuer URL. Leave
the issuer empty to use `security.issuer`.

| Role | Document | Issuer field |
| --- | --- | --- |
| Agent provider | `/.well-known/aauth-agent.json` | `aauth.ap_issuer` |
| Person server | `/.well-known/aauth-person.json` | `aauth.ps_issuer` |
| Access server | `/.well-known/aauth-access.json` | `aauth.as_issuer` |
| Resource | `/.well-known/aauth-resource.json` | `aauth.resource_issuer` |

A path issuer is served under that path. `http://127.0.0.1:8080/as`
publishes `http://127.0.0.1:8080/as/.well-known/aauth-access.json`.

Every document points `jwks_uri` at `{issuer}/aauth/jwks`. That key is
Ed25519. It is not the key at `/oidc/jwks`. The server creates it on
first start with the flag on and keeps it in `signing_keys`.

The documents name the person-token, auth-token, revocation, and
resource authorization URLs from
[draft-hardt-oauth-aauth-protocol-11](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/).
Those URLs are not handlers yet. A request to one of them is a 404.
