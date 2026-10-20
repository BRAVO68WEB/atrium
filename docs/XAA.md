# Cross-app access

Cross-app access lets a user sign in once at this server, then lets an
app they already approved ask a second authorization server for an
access token. The token in the middle is an ID-JAG. The draft is
[draft-ietf-oauth-identity-assertion-authz-grant-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/04/)
(21 May 2026). Okta calls that pattern XAA.

The draft expires on 22 November 2026. Nothing here runs until you set
`xaa.enabled` to true. A local access-token exchange stays available
either way. Configuration is in [Configuration](CONFIG.md).

## The two requests

The app makes two token requests. The user does not see a second
consent screen. You list the allowed apps and issuers in config. That
list is the policy.

1. At the identity provider, exchange the user's ID token for an
   ID-JAG.
2. At the resource authorization server, redeem that ID-JAG for an
   access token.

This server can play either role, or both, in one process.

## Ask this server for an ID-JAG

The app signs in with OpenID Connect and keeps the ID token. It then
calls `POST /oauth/token` with the token-exchange grant.

`requested_token_type` is
`urn:ietf:params:oauth:token-type:id-jag`. `subject_token` is the ID
token. `subject_token_type` is
`urn:ietf:params:oauth:token-type:id_token`. `audience` is the resource
authorization server's issuer. `scope` is the access you want there.

The client must list
`urn:ietf:params:oauth:grant-type:token-exchange`. A trust row must
name that client, that audience, and the requested scopes. The ID
token `aud` must contain this client, and `iss` must be this server.

The response puts the ID-JAG in `access_token`. `issued_token_type` is
`urn:ietf:params:oauth:token-type:id-jag`. `token_type` is `N_A`.
There is no refresh token. The assertion expires in five minutes. Its
header `typ` is `oauth-id-jag+jwt`.

The assertion carries `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, and
`client_id`. `client_id` is the client id at the resource
authorization server, which can differ from the client id here.
`scope` is the granted list. `email` is copied when the ID token has
it. The same ID token cannot be exchanged twice.

## Redeem an ID-JAG

`grant_type` is `urn:ietf:params:oauth:grant-type:jwt-bearer`.
`assertion` is the ID-JAG. The client authenticates as it does for any
other grant, and it must list this grant.

This server fetches `jwks_uri` for the matching `xaa.idps` row and
checks the signature. `aud` must be this server's issuer. `client_id`
must be the authenticated client. `jti` works once, until `exp`.

The local user is the account whose email matches the assertion. That
email must already be verified here. A missing account is
`invalid_grant`. This server does not create one.

The access token is the normal token for that user and client. It is
opaque unless `security.access_token_format` is `jwt`. There is no
refresh token. The ID-JAG is the grant, not a session.

## Discovery

With the flag on, OpenID discovery and authorization-server metadata
add `urn:ietf:params:oauth:grant-type:jwt-bearer` to
`grant_types_supported` and
`urn:ietf:params:oauth:grant-profile:id-jag` to
`authorization_grant_profiles_supported`. With the flag off, both
values are absent and the jwt-bearer grant returns
`unsupported_grant_type`.

## What stays out

This build does not accept a SAML assertion, `sub_id`, `tenant`, or
`aud_sub`. It does not provision users, accept rich authorization
requests, or show a browser screen for the trust list.

## Next steps

Set the rows in [Configuration](CONFIG.md). The token requests are
also listed in [API](API.md).
