"""Authentication provider for auth-token URL login."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

import voluptuous as vol
from homeassistant.auth.models import Credentials, UserMeta
from homeassistant.auth.providers import AUTH_PROVIDERS, AuthProvider, LoginFlow
from homeassistant.auth.providers.trusted_networks import InvalidUserError
from homeassistant.components.http import current_request

from .const import (
    AUTH_TOKEN_QUERY_PARAM,
    CONF_ALLOW_BYPASS_LOGIN,
    CONF_TOKEN_USER_MAP,
    DATA_CONFIG,
    DEFAULT_ALLOW_BYPASS_LOGIN,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


def _extract_auth_token(context: dict[str, Any]) -> str | None:
    """Extract auth token from current request or redirect URI."""
    request = current_request.get()
    if request is not None and (token := request.query.get(AUTH_TOKEN_QUERY_PARAM)):
        return token

    redirect_uri = context.get("redirect_uri")
    if isinstance(redirect_uri, str):
        values = parse_qs(urlparse(redirect_uri).query).get(AUTH_TOKEN_QUERY_PARAM)
        if values:
            return values[0]

    return None


@AUTH_PROVIDERS.register(DOMAIN)
class HATokenAuthProvider(AuthProvider):
    """Auth provider that accepts an allowlisted URL token."""

    DEFAULT_TITLE = "HA Token Auth"

    @property
    def type(self) -> str:
        """Return provider type."""
        return DOMAIN

    @property
    def support_mfa(self) -> bool:
        """This provider does not support MFA directly."""
        return False

    async def async_login_flow(self, context: dict[str, Any] | None) -> LoginFlow:
        """Return a flow to login."""
        assert context is not None

        config: dict[str, Any] = self.hass.data.get(DOMAIN, {}).get(DATA_CONFIG, {})
        token_user_map: dict[str, str] = config.get(CONF_TOKEN_USER_MAP, {})
        allow_bypass_login = config.get(
            CONF_ALLOW_BYPASS_LOGIN, DEFAULT_ALLOW_BYPASS_LOGIN
        )
        auth_token = _extract_auth_token(context)
        token_provided = isinstance(auth_token, str) and bool(auth_token)

        authorized_user_id: str | None = None
        if isinstance(auth_token, str):
            user_id = token_user_map.get(auth_token)
            if user_id and await self._async_user_exists(user_id):
                authorized_user_id = user_id
            elif user_id:
                _LOGGER.warning(
                    "Configured user_id '%s' for token no longer exists or is inactive",
                    user_id,
                )

        return HATokenAuthLoginFlow(
            self,
            authorized_user_id,
            allow_bypass_login,
            invalid_token=token_provided and authorized_user_id is None,
        )

    async def _async_user_exists(self, user_id: str) -> bool:
        """Check if a configured user exists and is active."""
        users = await self.store.async_get_users()
        return any(
            user.id == user_id and not user.system_generated and user.is_active
            for user in users
        )

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials."""
        raise NotImplementedError

    async def async_get_or_create_credentials(
        self, flow_result: dict[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        user_id = flow_result["user"]
        users = await self.store.async_get_users()

        for user in users:
            if user.id != user_id or user.system_generated or not user.is_active:
                continue

            for credential in await self.async_credentials():
                if credential.data.get("user_id") == user_id:
                    return credential

            cred = self.async_create_credentials({"user_id": user_id})
            await self.store.async_link_user(user, cred)
            return cred

        raise InvalidUserError


class HATokenAuthLoginFlow(LoginFlow):
    """Handler for the auth-token login flow."""

    def __init__(
        self,
        auth_provider: HATokenAuthProvider,
        authorized_user_id: str | None,
        allow_bypass_login: bool,
        invalid_token: bool,
    ) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)
        self._authorized_user_id = authorized_user_id
        self._allow_bypass_login = allow_bypass_login
        self._invalid_token = invalid_token

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Handle the init step."""
        if self._authorized_user_id is not None:
            return await self.async_finish({"user": self._authorized_user_id})

        if self._invalid_token:
            return self.async_show_form(
                step_id="init",
                data_schema=vol.Schema({}),
                errors={"base": "invalid_login"},
            )

        if self._allow_bypass_login or user_input is not None:
            return self.async_abort(reason="invalid_login")

        return self.async_show_form(step_id="init", data_schema=vol.Schema({}))
