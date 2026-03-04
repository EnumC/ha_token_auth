"""Config flow for ha_token_auth."""

from __future__ import annotations

from typing import Any

from homeassistant import config_entries
from homeassistant.core import callback
import voluptuous as vol

from .const import (
    CONF_ALLOW_BYPASS_LOGIN,
    CONF_ALLOWLIST,
    CONF_TOKEN_USER_MAP,
    CONF_USER_ID,
    DEFAULT_ALLOW_BYPASS_LOGIN,
    DOMAIN,
)
from .helpers import normalize_allowlist, normalize_token_user_map


async def _async_get_user_options(hass) -> dict[str, str]:
    """Return active, non-system users as id -> display name."""
    users = await hass.auth.async_get_users()
    return {
        user.id: user.name
        for user in users
        if not user.system_generated and user.is_active
    }


def _effective_token_user_map(
    data: dict[str, Any], options: dict[str, Any], user_options: dict[str, str]
) -> list[dict[str, str]]:
    """Return token/user mappings with options first, then legacy fallback."""
    if CONF_TOKEN_USER_MAP in options:
        return normalize_token_user_map(options.get(CONF_TOKEN_USER_MAP, []))
    if options:
        # Options were explicitly saved, so missing token_user_map means no tokens.
        return []
    if CONF_TOKEN_USER_MAP in data:
        return normalize_token_user_map(data.get(CONF_TOKEN_USER_MAP, []))

    legacy_user_id = data.get(CONF_USER_ID)
    if legacy_user_id not in user_options:
        return []

    return [
        {"token": token, "user_id": legacy_user_id}
        for token in normalize_allowlist(data.get(CONF_ALLOWLIST, []))
    ]


def _user_fields(user_options: dict[str, str]) -> dict[str, str]:
    """Build UI field labels mapped to user IDs."""
    fields: dict[str, str] = {}
    used_labels: set[str] = {CONF_ALLOW_BYPASS_LOGIN}

    for user_id, user_name in user_options.items():
        label_base = user_name or user_id
        label = label_base
        if label in used_labels:
            label = f"{label_base} ({user_id[:8]})"
        while label in used_labels:
            label = f"{label}*"

        used_labels.add(label)
        fields[label] = user_id

    return fields


def _defaults_by_user_id(token_user_map: list[dict[str, str]]) -> dict[str, str]:
    """Build default token value by user_id from stored mapping."""
    defaults: dict[str, str] = {}

    for entry in token_user_map:
        user_id = entry["user_id"]
        if user_id not in defaults:
            defaults[user_id] = entry["token"]

    return defaults


def _options_to_storage(
    user_input: dict[str, Any], user_fields: dict[str, str]
) -> tuple[dict[str, Any], str | None]:
    """Convert UI form input to stored config."""
    seen_tokens: set[str] = set()
    token_user_map: list[dict[str, str]] = []

    for field, user_id in user_fields.items():
        token = str(user_input.get(field, "")).strip()
        if not token:
            continue
        if token in seen_tokens:
            return {}, "duplicate_token"

        seen_tokens.add(token)
        token_user_map.append({"token": token, "user_id": user_id})

    return {
        CONF_ALLOW_BYPASS_LOGIN: user_input[CONF_ALLOW_BYPASS_LOGIN],
        CONF_TOKEN_USER_MAP: normalize_token_user_map(token_user_map),
    }, None


def _form_schema(
    user_fields: dict[str, str],
    defaults_by_user_id: dict[str, str],
    allow_bypass_login_default: bool,
) -> vol.Schema:
    """Build a form schema with one token text box per user."""
    schema: dict[Any, Any] = {}

    for label, user_id in user_fields.items():
        field_kwargs: dict[str, Any] = {}
        if suggested := defaults_by_user_id.get(user_id):
            field_kwargs["description"] = {"suggested_value": suggested}

        schema[vol.Optional(label, **field_kwargs)] = str

    schema[
        vol.Required(
            CONF_ALLOW_BYPASS_LOGIN, default=allow_bypass_login_default
        )
    ] = bool

    return vol.Schema(schema)


class HATokenAuthConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for ha_token_auth."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return HATokenAuthOptionsFlow(config_entry)

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle the initial step."""
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        user_options = await _async_get_user_options(self.hass)
        if not user_options:
            return self.async_abort(reason="no_user_available")

        user_fields = _user_fields(user_options)

        errors: dict[str, str] = {}
        if user_input is not None:
            data, error = _options_to_storage(user_input, user_fields)
            if error is None:
                return self.async_create_entry(title="HA Token Auth", data=data)
            errors["base"] = error

        return self.async_show_form(
            step_id="user",
            data_schema=_form_schema(
                user_fields,
                defaults_by_user_id={},
                allow_bypass_login_default=DEFAULT_ALLOW_BYPASS_LOGIN,
            ),
            errors=errors,
        )


class HATokenAuthOptionsFlow(config_entries.OptionsFlow):
    """Handle options for ha_token_auth."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Manage options."""
        user_options = await _async_get_user_options(self.hass)
        if not user_options:
            return self.async_abort(reason="no_user_available")

        data = self._config_entry.data
        options = self._config_entry.options
        merged = {**data, **options}
        token_user_map = _effective_token_user_map(data, options, user_options)

        user_fields = _user_fields(user_options)
        defaults_by_user_id = _defaults_by_user_id(token_user_map)

        errors: dict[str, str] = {}
        if user_input is not None:
            options, error = _options_to_storage(user_input, user_fields)
            if error is None:
                return self.async_create_entry(title="", data=options)
            errors["base"] = error

        return self.async_show_form(
            step_id="init",
            data_schema=_form_schema(
                user_fields,
                defaults_by_user_id=defaults_by_user_id,
                allow_bypass_login_default=merged.get(
                    CONF_ALLOW_BYPASS_LOGIN, DEFAULT_ALLOW_BYPASS_LOGIN
                ),
            ),
            errors=errors,
        )
