# Push devices

This is authenticator registration from
[draft-bandyopadhayaya-oauth-push-device-00](https://datatracker.ietf.org/doc/draft-bandyopadhayaya-oauth-push-device/).
It is not the device-code grant on `/oauth/device`. Nothing here wakes
a phone. CIBA stays poll-only. Configuration is in
[Configuration](CONFIG.md).

`push.enabled` defaults to false. While it is false,
`/.well-known/oauth-push-notification` and `/push` are not mounted.

When you turn it on, a signed-in user opens `/push/enroll`. The page
shows a QR code and a registration token in the address fragment. An
authenticator posts that token and a P-256 public key to
`/push/register`. The response is an opaque device credential. The
credential is not an OAuth access token.

The signed-in user lists devices at `GET /push/devices`. Each row
includes `attestation_status`. The value is `not_checked`. The device
revokes itself at `POST /push/revoke` and rotates its key at
`POST /push/rotate-key`. Both calls require a DPoP proof for the
registered key. Revoke keeps the credential, so the same call can be
repeated. Rotation keeps the previous key for
`push.grace_period_seconds` (300 seconds unless you set it). A later
call with the new key drops the previous key. Send `reason` as
`compromised` to drop it immediately. Discovery advertises `poll`
only. There is no push relay. An `attestation` value is stored.
When `client_attestation_required` is true, an empty value is
rejected. The value is not verified.

`POST /push/register` accepts `replaces_device_id`. The new device is
stored, and then the named device is revoked. You can replace a device
when the account is already at `max_devices_per_user`.

`POST /push/devices` with `device_id` marks that device primary. A
sign-in uses the primary device when it is still active. Otherwise it
uses the latest active device.

Management calls `POST /api/users/{id}/push/revoke` to revoke every
device for that user, and `POST /api/users/{id}/push/enroll` to issue a
registration token and an enroll URL.

A CIBA request for a user with an active device waits on that device.
`/bc-authorize` returns `binding_message` when one is stored. The
client then polls `/oauth/token` as usual. A revoked device makes that
poll return `device_revoked`. An `interaction_type` below
`push.minimum_interaction_type`, or one the device did not register,
is `invalid_request`.

`boolean` is approve or deny. `number_choose` is three numbers, and
approve counts only when the posted number matches. `input_manual` is
a typed code, and approve counts only when the posted code matches.
Deny does not need the check. `/push/approve` is the browser page.
`GET /push/pending` and `POST /push/pending` are the same decision for
the device credential. Send `device_id`, `Authorization: Bearer`, and
a DPoP proof. After the first call, send the `Replay-Nonce` from the
previous response. `ping` and `push` delivery are not sent yet.
