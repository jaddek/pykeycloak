# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from urllib.parse import urlencode

from pykeycloak.core.clients import HttpMethod
from pykeycloak.core.exceptions import AccessTokenIsRequiredError
from pykeycloak.core.helpers import dataclass_from_dict
from pykeycloak.core.protocols import KeycloakResponseProtocol
from pykeycloak.core.token_manager import AuthToken, TokenManager
from pykeycloak.core.urls import (
    REALM_CLIENT_OPENID_URL_AUTH,
    REALM_CLIENT_OPENID_URL_AUTH_DEVICE,
    REALM_CLIENT_OPENID_URL_CERTS,
    REALM_CLIENT_OPENID_URL_INTROSPECT,
    REALM_CLIENT_OPENID_URL_LOGOUT,
    REALM_CLIENT_OPENID_URL_REVOKE,
    REALM_CLIENT_OPENID_URL_TOKEN,
    REALM_CLIENT_OPENID_URL_USERINFO,
)

from ._base import KeycloakProviderBase
from .payloads import (
    ClientCredentialsLoginPayload,
    ConfidentialClientRevokePayload,
    ObtainTokenPayload,
    PublicClientRevokePayload,
    RefreshTokenPayload,
    RTPExchangeTokenPayload,
    RTPIntrospectionPayload,
    SSOLoginPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
)


class AuthProvider:
    def __init__(self, base: KeycloakProviderBase, token_manager: TokenManager) -> None:
        self._base = base
        self._token_manager = token_manager

        async def _on_token_expired(
            refresh_token: str | None,
        ) -> KeycloakResponseProtocol:
            if refresh_token:
                return await self.refresh_token_async(
                    payload=RefreshTokenPayload(refresh_token=refresh_token)
                )
            return await self.obtain_token_async(
                payload=ClientCredentialsLoginPayload()
            )

        self._token_manager.init_update_access_token_api(_on_token_expired)

    async def get_client_access_token(self) -> str:
        token = await self._token_manager.get_valid_token()
        if not token.access_token:
            raise AccessTokenIsRequiredError(
                "Access token should be initialized first via obtain_token_async"
            )
        return token.access_token

    async def obtain_token_async(
        self, payload: ObtainTokenPayload
    ) -> KeycloakResponseProtocol:
        headers = self._base.openid_basic_headers(
            token=self._base.realm_client.base64_encoded_client_secret()
        )

        response = await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_OPENID_URL_TOKEN),
            data=payload.to_dict(),
            headers=headers,
        )

        self._token_manager.update_auth_tokens(
            dataclass_from_dict(response.json(), AuthToken)
        )

        return response

    async def refresh_token_async(
        self,
        payload: RefreshTokenPayload | RTPExchangeTokenPayload,
    ) -> KeycloakResponseProtocol:
        if not self._base.realm_client.is_confidential:
            raise ValueError(
                "Introspection could be invoked only by confidential clients"
            )

        headers: dict[str, str] | None = None

        match payload:
            case payload if isinstance(payload, RTPExchangeTokenPayload):
                headers = self._base.openid_bearer_headers(
                    token=str(payload.refresh_token)
                )
            case payload if isinstance(payload, RefreshTokenPayload):
                headers = self._base.openid_basic_headers(
                    token=self._base.realm_client.base64_encoded_client_secret()
                )
            case _:
                raise TypeError(
                    f"Unsupported payload type: {type(payload).__name__}. "
                    "Expected RTPExchangeTokenPayload or RefreshTokenPayload"
                )

        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_OPENID_URL_TOKEN),
            data=payload.to_dict(),
            headers=headers,
        )

    def get_sso_redirect_url(self, payload: SSOLoginPayload) -> str:
        path = self._base.build_url(path=REALM_CLIENT_OPENID_URL_AUTH)
        query_string = urlencode(payload.to_dict())
        return self._base.build_full_url(path=path, query=query_string)

    async def introspect_token_async(
        self,
        payload: RTPIntrospectionPayload | TokenIntrospectionPayload,
    ) -> KeycloakResponseProtocol:
        if not self._base.realm_client.is_confidential:
            raise ValueError(
                "Introspection could be invoked only by confidential clients"
            )

        headers: dict[str, str] | None = None

        match payload:
            case payload if isinstance(payload, RTPIntrospectionPayload):
                headers = self._base.openid_bearer_headers(token=str(payload.token))
            case payload if isinstance(payload, TokenIntrospectionPayload):
                headers = self._base.openid_basic_headers(
                    token=self._base.realm_client.base64_encoded_client_secret()
                )
            case _:
                raise TypeError(
                    f"Unsupported payload type: {type(payload).__name__}. "
                    "Expected RTPIntrospectionPayload or TokenIntrospectionPayload"
                )

        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_OPENID_URL_INTROSPECT),
            data=payload.to_dict(),
            headers=headers,
        )

    async def auth_device_async(self) -> KeycloakResponseProtocol:
        headers: dict[str, str] | None = None
        data = {
            "client_id": self._base.realm_client.client_id,
            "scope": "openid profile email",
        }

        if self._base.realm_client.is_confidential:
            headers = self._base.openid_basic_headers(
                token=self._base.realm_client.base64_encoded_client_secret()
            )

        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_OPENID_URL_AUTH_DEVICE),
            headers=headers,
            data=data,
        )

    async def get_certs_async(self) -> KeycloakResponseProtocol:
        access_token = await self.get_client_access_token()
        headers = self._base.openid_bearer_headers(token=access_token)

        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_OPENID_URL_CERTS),
            headers=headers,
        )

    async def logout_async(self, refresh_token: str) -> KeycloakResponseProtocol:
        payload = {
            "client_id": self._base.realm_client.client_id,
            "refresh_token": refresh_token,
        }

        if self._base.realm_client.client_secret:
            payload |= {"client_secret": self._base.realm_client.client_secret}

        headers = self._base.openid_bearer_headers(
            token=self._base.realm_client.base64_encoded_client_secret()
        )

        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_OPENID_URL_LOGOUT),
            data=payload,
            headers=headers,
        )

    async def revoke_async(self, refresh_token: str) -> KeycloakResponseProtocol:
        payload: ConfidentialClientRevokePayload | PublicClientRevokePayload | None = (
            None
        )
        headers: dict[str, str] | None = None

        match self._base.realm_client.is_confidential:
            case True:
                payload = ConfidentialClientRevokePayload(token=refresh_token)
                headers = self._base.openid_basic_headers(
                    token=self._base.realm_client.base64_encoded_client_secret()
                )
            case False:
                payload = PublicClientRevokePayload(
                    client_id=self._base.realm_client.client_id, token=refresh_token
                )
                headers = self._base.openid_bearer_headers(token=str(payload.token))

        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_OPENID_URL_REVOKE),
            data=payload.to_dict(),
            headers=headers,
        )

    async def get_user_info_async(
        self, *, access_token: str
    ) -> KeycloakResponseProtocol:
        headers = self._base.openid_bearer_headers(token=access_token)

        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_OPENID_URL_USERINFO),
            headers=headers,
        )

    async def get_uma_permission_async(
        self,
        payload: UMAAuthorizationPayload,
    ) -> KeycloakResponseProtocol:
        headers = self._base.openid_basic_headers(
            token=self._base.realm_client.base64_encoded_client_secret()
        )

        data = payload.to_dict()

        if not data.get("audience"):
            data["audience"] = self._base.realm_client.client_id

        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_OPENID_URL_TOKEN),
            data=data,
            headers=headers,
        )
