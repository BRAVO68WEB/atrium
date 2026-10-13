# Branding

Auth pages read the `branding` block. Restart the server after a change.
Key names and defaults are in [Configuration](CONFIG.md).

## Copy and color

`product_name`, `login_title`, `username_label`, `password_label`,
`submit_label`, and `footer_text` are the visible strings. Empty copy
falls back to the built-in labels. `primary_color`, `background_color`,
and `text_color` are `#rgb` or `#rrggbb`. An empty primary color becomes
`#0066ff`. With no `background_color` and no `background_file`, the page
behind the card is a deep shade of the primary color.

`support_url`, `privacy_url`, and `terms_url` are optional links in the
page footer.

When `security.login_identifier` is `email` and `username_label` is empty
or `Username`, the login field label is `Email` and the field
autocomplete is `email`. Set `username_label` to any other string to keep
your own label.

`show_register` and `show_forgot_password` default to true when the keys
are omitted. `show_register: false` hides the register link and leaves
signup available. `security.disable_registration` closes self-service
signup: `GET` and `POST /register` and `POST /api/account/register`
return 403. Management `POST /api/users` still creates accounts.

## Assets

`assets_dir` is a directory of files named by `logo_file`,
`favicon_file`, and `background_file`, plus an optional `custom.css`.
The server serves one file at `/branding/assets/{name}`. An image hosted
on another site does not load through this path.

Allowed extensions are png, jpg, jpeg, gif, webp, svg, ico, and css.
Each file is at most 1 MiB. Names stay inside `assets_dir`.
`background_file` accepts only png, jpg, jpeg, gif, webp, and svg.

When `background_file` is set, that image covers the page behind the
card. `background_color` shows through only while the image is not set.
The card stays white, and footer text and links stay in the card so they
remain readable on any photo. Set a custom typeface in `custom.css`.

## HTML overlays

`templates` is a directory of HTML files, read when the process starts.
A file replaces the built-in page with the same base name. A name you
omit stays on the built-in page. An empty file or a file that does not
parse stops startup.

Built-in pages:

- `chrome.html` is the shared header on every auth page
- `login.html`, `mfa.html`, `register.html`, `consent.html`
- `forgot.html`, `reset.html`, `verify_email.html`
- `device.html`, `organization.html`, `logout.html`, `mfa_enroll.html`
- `docs.html`

A replacement `login.html` must POST to `/login` and keep these field
names: `username`, `password`, `client_id`, `redirect_uri`,
`response_type`, `scope`, `state`, `nonce`, `code_challenge`,
`code_challenge_method`, `request_uri`, `prompt`, `login_hint`,
`resource`, `requested_actor`, and `next`.

## Related

[Deploy](DEPLOY.md) covers restarting the process.
[API](API.md) lists the browser routes.
