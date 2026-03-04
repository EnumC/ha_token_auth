# HA Token Auth for Home Assistant

Custom auth provider that signs in users via `?auth-token=...` in the URL.

## Current behavior

- Per-user token fields in config/options flow
- Empty token field disables token login for that user
- Duplicate tokens are not allowed
- Optional fallback to other login providers

## Install

1. Copy `custom_components/ha_token_auth` into your Home Assistant `config/custom_components/` directory.
2. Restart Home Assistant.
3. Go to **Settings -> Devices & Services -> Add Integration**.
4. Add **HA Token Auth** and configure tokens for users.

## Usage

`https://your-home-assistant.example.com/?auth-token=YOUR_TOKEN`

If the token is configured for a user, Home Assistant logs in as that user.

For HACS installation details, see the repository root `README.md`.
