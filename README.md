# HA Token Auth (Home Assistant Custom Component)

`ha_token_auth` is a Home Assistant custom integration that adds URL-token based login.

It reads an `auth-token` query parameter from the authorize/login request and, when valid, signs in as the mapped Home Assistant user.

It's useful for kiosk-like environment where you can specify a predefined URL.
Also useful as a bookmark on Tesla vehicles to always be logged in to HA.

## What it does

- Adds a custom auth provider: `ha_token_auth`
- Supports **per-user token configuration** from the UI
- Lets you leave token fields empty to disable token login for specific users
- Optionally allows fallback to other login providers
- Returns a clear error message for invalid/missing tokens

## How token mapping works

In integration options, each active user gets a token text box:

- Enter a token for a user: that token logs in as that user
- Leave empty: token login is disabled for that user
- Duplicate tokens are rejected

## Install with HACS

[![Add to HACS](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=EnumC&repository=ha_token_auth&category=integration)


1. Open **HACS** in Home Assistant.
2. Go to **HACS -> Integrations -> ⋮ (menu) -> Custom repositories**.
3. Add this repository URL.
4. Set category to **Integration**.
5. Click **Add**.
6. Find **HA Token Auth** in HACS and click **Download**.
7. Restart Home Assistant.
8. Go to **Settings -> Devices & Services -> Add Integration**.
9. Add **HA Token Auth** and configure tokens.

## Manual install

1. Copy `custom_components/ha_token_auth` into:
   - `<config>/custom_components/ha_token_auth`
2. Restart Home Assistant.
3. Add the integration from **Settings -> Devices & Services**.

## Usage

Example URL:

`http://localhost:8123/?auth-token=YOUR_TOKEN`

If the token is mapped to a user, login is completed for that user.

## Troubleshooting

If the authorize page shows `Login aborted:` and a `Start over` button, the
`auth-token` is missing or invalid.

## Security notes

- Treat tokens like passwords.
- Use HTTPS in production.
- Use long random tokens.
- Rotate tokens periodically.
