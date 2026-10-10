"""HA Token Auth integration."""

from __future__ import annotations

from collections import OrderedDict
import logging
import os.path
import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType

from .const import (
    AUTH_TOKEN_QUERY_PARAM,
    CONF_ALLOW_BYPASS_LOGIN,
    CONF_ALLOWLIST,
    CONF_TOKEN_USER_MAP,
    CONF_USER_ID,
    DATA_CONFIG,
    DATA_UPDATE_LISTENERS,
    DATA_VIEW_REGISTERED,
    DEFAULT_ALLOW_BYPASS_LOGIN,
    DOMAIN,
)
from .helpers import normalize_allowlist, normalize_token_user_map
from .provider import HATokenAuthProvider

_LOGGER = logging.getLogger(__name__)
_FORWARD_SCRIPT_URL = "/ha_token_auth/forward-token.js"


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the integration."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up from a config entry."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data[DATA_CONFIG] = _entry_to_config(entry)

    if not domain_data.get(DATA_VIEW_REGISTERED):
        await _register_token_forward_script(hass)
        domain_data[DATA_VIEW_REGISTERED] = True

    _inject_provider(hass)

    listeners: dict[str, Any] = domain_data.setdefault(DATA_UPDATE_LISTENERS, {})
    listeners[entry.entry_id] = entry.add_update_listener(async_reload_entry)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    domain_data = hass.data.get(DOMAIN, {})
    listeners: dict[str, Any] = domain_data.get(DATA_UPDATE_LISTENERS, {})
    if listener := listeners.pop(entry.entry_id, None):
        listener()

    remaining = [
        config_entry
        for config_entry in hass.config_entries.async_entries(DOMAIN)
        if config_entry.entry_id != entry.entry_id
    ]

    if remaining:
        domain_data[DATA_CONFIG] = _entry_to_config(remaining[0])
        _inject_provider(hass)
        return True

    _remove_provider(hass)
    hass.data.pop(DOMAIN, None)
    return True


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry after an update."""
    await hass.config_entries.async_reload(entry.entry_id)


def _entry_to_config(entry: ConfigEntry) -> dict[str, Any]:
    """Merge config entry data and options into runtime config."""
    merged = {**entry.data, **entry.options}

    if CONF_TOKEN_USER_MAP in entry.options:
        token_entries = normalize_token_user_map(
            entry.options.get(CONF_TOKEN_USER_MAP, [])
        )
    elif entry.options:
        # Options were explicitly saved, so missing token_user_map means no tokens.
        token_entries = []
    elif CONF_TOKEN_USER_MAP in entry.data:
        token_entries = normalize_token_user_map(
            entry.data.get(CONF_TOKEN_USER_MAP, [])
        )
    else:
        legacy_user_id = merged.get(CONF_USER_ID)
        token_entries = (
            [
                {"token": token, "user_id": legacy_user_id}
                for token in normalize_allowlist(merged.get(CONF_ALLOWLIST, []))
            ]
            if legacy_user_id
            else []
        )
    token_lookup = {
        token_entry["token"]: token_entry["user_id"] for token_entry in token_entries
    }

    return {
        CONF_ALLOW_BYPASS_LOGIN: merged.get(
            CONF_ALLOW_BYPASS_LOGIN, DEFAULT_ALLOW_BYPASS_LOGIN
        ),
        CONF_TOKEN_USER_MAP: token_lookup,
    }


async def _register_token_forward_script(hass: HomeAssistant) -> None:
    """Register frontend script that forwards URL auth-token to login flow."""
    if not _is_route_registered(hass, _FORWARD_SCRIPT_URL):
        try:
            await hass.http.async_register_static_paths(
                [
                    StaticPathConfig(
                        _FORWARD_SCRIPT_URL,
                        os.path.join(os.path.dirname(__file__), "forward-token.js"),
                        True,
                    )
                ]
            )
        except RuntimeError as err:
            # Reload can race with existing routes; ignore duplicate registration.
            if "already registered" not in str(err):
                raise
            _LOGGER.debug("Static path already registered for %s", _FORWARD_SCRIPT_URL)
    add_extra_js_url(hass, _FORWARD_SCRIPT_URL)


def _is_route_registered(hass: HomeAssistant, url_path: str) -> bool:
    """Return True if the given URL path already exists in the HTTP router."""
    for resource in hass.http.app.router.resources():
        canonical = getattr(resource, "canonical", None)
        if canonical == url_path:
            return True
    return False


_OIDC_DOMAIN = "auth_oidc"
_OIDC_PAGE_MODULE = "custom_components.auth_oidc.endpoints.injected_auth_page"


def _inject_provider(hass: HomeAssistant) -> None:
    """Inject provider first, or right after auth_oidc which must stay first."""
    provider = HATokenAuthProvider(hass, hass.auth._store, {"id": DOMAIN})
    existing = [
        (key, existing_provider)
        for key, existing_provider in hass.auth._providers.items()
        if existing_provider.type != DOMAIN
    ]
    index = 1 if existing and existing[0][1].type == _OIDC_DOMAIN else 0
    existing.insert(index, ((provider.type, provider.id), provider))
    hass.auth._providers = OrderedDict(existing)
    _patch_oidc_redirect()


def _request_has_token(req: Any) -> bool:
    """Return True if an authorize request carries an auth token."""
    if req.query.get(AUTH_TOKEN_QUERY_PARAM):
        return True
    redirect_uri = req.query.get("redirect_uri")
    if not redirect_uri:
        return False
    return bool(parse_qs(urlparse(redirect_uri).query).get(AUTH_TOKEN_QUERY_PARAM))


def _patch_oidc_redirect() -> None:
    """Keep auth_oidc from redirecting token logins to its SSO page."""
    module = sys.modules.get(_OIDC_PAGE_MODULE)
    page = getattr(module, "OIDCInjectedAuthPage", None)
    original = getattr(page, "_should_do_oidc_redirect", None)
    if original is None or getattr(original, "_ha_token_auth", False):
        return

    def _should_do_oidc_redirect(self: Any, req: Any) -> bool:
        if _request_has_token(req):
            return False
        return original(self, req)

    _should_do_oidc_redirect._ha_token_auth = True
    page._should_do_oidc_redirect = _should_do_oidc_redirect


def _remove_provider(hass: HomeAssistant) -> None:
    """Remove provider from auth providers."""
    providers = OrderedDict(
        (key, provider)
        for key, provider in hass.auth._providers.items()
        if provider.type != DOMAIN
    )
    hass.auth._providers = providers
