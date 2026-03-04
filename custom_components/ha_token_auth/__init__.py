"""HA Token Auth integration."""

from __future__ import annotations

from collections import OrderedDict
from http import HTTPStatus
from ipaddress import ip_address
import os.path
from typing import Any, TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from aiohttp.web import Request, Response
from homeassistant import data_entry_flow
from homeassistant.components.auth import DOMAIN as AUTH_DOMAIN
from homeassistant.components.auth import indieauth
from homeassistant.components.auth.login_flow import LoginFlowIndexView
from homeassistant.components.auth.login_flow import LoginFlowResourceView
from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import StaticPathConfig
from homeassistant.components.http.ban import log_invalid_auth, process_wrong_login
from homeassistant.components.http.data_validator import RequestDataValidator
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
import voluptuous as vol

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

if TYPE_CHECKING:
    from homeassistant.components.http import FastUrlDispatcher
    from aiohttp.web_urldispatcher import AbstractResource, UrlDispatcher

INVALID_LOGIN_REASONS = {"invalid_login", "invalid_auth"}
INVALID_LOGIN_MESSAGE = "Invalid or missing auth-token URL parameter."


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the integration."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up from a config entry."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data[DATA_CONFIG] = _entry_to_config(entry)

    if not domain_data.get(DATA_VIEW_REGISTERED):
        _replace_login_flow_view(hass)
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

    token_user_map = normalize_token_user_map(merged.get(CONF_TOKEN_USER_MAP, []))
    if token_user_map:
        token_lookup = {entry["token"]: entry["user_id"] for entry in token_user_map}
    else:
        legacy_user_id = merged.get(CONF_USER_ID)
        token_lookup = (
            {
                token: legacy_user_id
                for token in normalize_allowlist(merged.get(CONF_ALLOWLIST, []))
            }
            if legacy_user_id
            else {}
        )

    return {
        CONF_ALLOW_BYPASS_LOGIN: merged.get(
            CONF_ALLOW_BYPASS_LOGIN, DEFAULT_ALLOW_BYPASS_LOGIN
        ),
        CONF_TOKEN_USER_MAP: token_lookup,
    }


def _replace_login_flow_view(hass: HomeAssistant) -> None:
    """Replace login flow view so request context can be passed to providers."""
    store_result = hass.data[AUTH_DOMAIN]
    router: FastUrlDispatcher | UrlDispatcher = hass.http.app.router

    for route in list(router._resources):
        if route.canonical in (
            RequestLoginFlowIndexView.url,
            RequestLoginFlowResourceView.url,
        ):
            hass.http.app.router._resources.remove(route)

    if hasattr(router, "_resource_index"):
        resource_index: dict[str, list[AbstractResource]] = router._resource_index
        for url in (RequestLoginFlowIndexView.url, RequestLoginFlowResourceView.url):
            routes = resource_index.get(url, [])
            for route in list(routes):
                if route.canonical == url:
                    routes.remove(route)

    hass.http.register_view(
        RequestLoginFlowIndexView(hass.auth.login_flow, store_result, hass)
    )
    hass.http.register_view(
        RequestLoginFlowResourceView(hass.auth.login_flow, store_result)
    )


def _is_auth_token_provider(handler: tuple[str, ...] | str | None) -> bool:
    """Return if the selected handler is this custom auth provider."""
    if isinstance(handler, tuple):
        return bool(handler) and handler[0] == DOMAIN
    return handler == DOMAIN


def _is_invalid_login_flow_result(result: dict[str, Any]) -> bool:
    """Return True when result indicates invalid login for this provider."""
    if not _is_auth_token_provider(result.get("handler")):
        return False

    result_type = result.get("type")
    if result_type == data_entry_flow.FlowResultType.FORM:
        errors = result.get("errors") or {}
        return errors.get("base") in INVALID_LOGIN_REASONS

    if result_type == data_entry_flow.FlowResultType.ABORT:
        return result.get("reason") in INVALID_LOGIN_REASONS

    return False


async def _register_token_forward_script(hass: HomeAssistant) -> None:
    """Register frontend script that forwards URL auth-token to login flow."""
    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/ha_token_auth/forward-token.js",
                os.path.join(os.path.dirname(__file__), "forward-token.js"),
                True,
            )
        ]
    )
    add_extra_js_url(hass, "/ha_token_auth/forward-token.js")


def _inject_provider(hass: HomeAssistant) -> None:
    """Inject provider at the start of provider list."""
    provider = HATokenAuthProvider(hass, hass.auth._store, {"id": DOMAIN})
    providers = OrderedDict()
    providers[(provider.type, provider.id)] = provider

    for key, existing_provider in hass.auth._providers.items():
        if existing_provider.type == DOMAIN:
            continue
        providers[key] = existing_provider

    hass.auth._providers = providers


def _remove_provider(hass: HomeAssistant) -> None:
    """Remove provider from auth providers."""
    providers = OrderedDict(
        (key, provider)
        for key, provider in hass.auth._providers.items()
        if provider.type != DOMAIN
    )
    hass.auth._providers = providers


def _extract_auth_token(request: Request, redirect_uri: str) -> str | None:
    """Extract auth token from request and redirect URI query strings."""
    if token := request.query.get(AUTH_TOKEN_QUERY_PARAM):
        return token

    parsed = urlparse(redirect_uri)
    values = parse_qs(parsed.query).get(AUTH_TOKEN_QUERY_PARAM)
    if values:
        return values[0]

    return None


def _get_actual_ip(request: Request) -> str:
    """Get remote from request without considering reverse-proxy override."""
    peername = getattr(request, "_transport_peername", None)
    if isinstance(peername, (list, tuple)) and peername:
        return str(peername[0])
    if isinstance(peername, str):
        return peername
    return request.remote or "127.0.0.1"


class RequestLoginFlowIndexView(LoginFlowIndexView):
    """Login flow view that passes request and auth-token into flow context."""

    def __init__(self, flow_mgr: Any, store_result: Any, hass: HomeAssistant) -> None:
        """Initialize view."""
        super().__init__(flow_mgr, store_result)
        self.hass = hass

    @RequestDataValidator(
        vol.Schema(
            {
                vol.Required("client_id"): str,
                vol.Required("handler"): vol.Any(str, list),
                vol.Required("redirect_uri"): str,
                vol.Optional("type", default="authorize"): str,
            }
        )
    )
    @log_invalid_auth
    async def post(self, request: Request, data: dict[str, Any]) -> Response:
        """Create a new login flow."""
        client_id: str = data["client_id"]
        redirect_uri: str = data["redirect_uri"]

        if not indieauth.verify_client_id(client_id):
            return self.json_message("Invalid client id", HTTPStatus.BAD_REQUEST)

        handler: tuple[str, ...] | str
        if isinstance(data["handler"], list):
            handler = tuple(data["handler"])
        else:
            handler = data["handler"]

        auth_token = _extract_auth_token(request, redirect_uri)
        actual_ip = _get_actual_ip(request)
        remote_ip = request.remote or actual_ip

        try:
            result = await self._flow_mgr.async_init(
                handler,  # type: ignore[arg-type]
                context={
                    "request": request,
                    "auth_token": auth_token,
                    "ip_address": ip_address(remote_ip),
                    "conn_ip_address": ip_address(actual_ip),
                    "credential_only": data.get("type") == "link_user",
                    "redirect_uri": redirect_uri,
                },
            )
        except data_entry_flow.UnknownHandler:
            return self.json_message("Invalid handler specified", HTTPStatus.NOT_FOUND)
        except data_entry_flow.UnknownStep:
            return self.json_message(
                "Handler does not support init", HTTPStatus.BAD_REQUEST
            )

        if _is_invalid_login_flow_result(result):
            await process_wrong_login(request)
            return self.json_message(INVALID_LOGIN_MESSAGE, HTTPStatus.FORBIDDEN)

        return await self._async_flow_result_to_response(request, client_id, result)


class RequestLoginFlowResourceView(LoginFlowResourceView):
    """Login flow resource view that returns explicit 403 invalid token errors."""

    @RequestDataValidator(
        vol.Schema(
            {vol.Required("client_id"): str},
            extra=vol.ALLOW_EXTRA,
        )
    )
    @log_invalid_auth
    async def post(self, request: Request, data: dict[str, Any], flow_id: str) -> Response:
        """Handle progressing a login flow request."""
        client_id: str = data.pop("client_id")

        if not indieauth.verify_client_id(client_id):
            return self.json_message("Invalid client id", HTTPStatus.BAD_REQUEST)

        try:
            flow = self._flow_mgr.async_get(flow_id)
            if flow["context"]["ip_address"] != ip_address(request.remote):  # type: ignore[arg-type]
                return self.json_message("IP address changed", HTTPStatus.BAD_REQUEST)
            result = await self._flow_mgr.async_configure(flow_id, data)
        except data_entry_flow.UnknownFlow:
            return self.json_message("Invalid flow specified", HTTPStatus.NOT_FOUND)
        except vol.Invalid:
            return self.json_message("User input malformed", HTTPStatus.BAD_REQUEST)

        if _is_invalid_login_flow_result(result):
            await process_wrong_login(request)
            return self.json_message(INVALID_LOGIN_MESSAGE, HTTPStatus.FORBIDDEN)

        return await self._async_flow_result_to_response(request, client_id, result)
