# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from typing import Any

from pykeycloak.core.clients import HttpMethod, KeycloakHttpClientAsync
from pykeycloak.core.headers import HeadersProtocol
from pykeycloak.core.protocols import KeycloakResponseProtocol
from pykeycloak.core.realm import RealmClient


class KeycloakProviderBase:
    def __init__(
        self,
        *,
        realm_client: RealmClient,
        kc_headers: HeadersProtocol,
        kc_client: KeycloakHttpClientAsync,
    ) -> None:
        self._realm_client: RealmClient = realm_client
        self._kc_headers = kc_headers
        self._kc_client = kc_client

    @property
    def realm_client(self) -> RealmClient:
        return self._realm_client

    def build_url(self, path: str, **kwargs: Any) -> str:
        params = {
            "realm": str(self._realm_client.realm_name),
            "client_id": str(self._realm_client.client_id),
            "client_uuid": str(self._realm_client.client_uuid),
            **{k: str(v) for k, v in kwargs.items()},
        }
        return path.format(**params)

    async def request_async(
        self,
        method: HttpMethod,
        url: str,
        **kwargs: Any,
    ) -> KeycloakResponseProtocol:
        return await self._kc_client.request_async(method=method, url=url, **kwargs)

    def bearer_headers(self, token: str) -> dict[str, str]:
        return self._kc_headers.keycloak_bearer(bearer_token=token)

    def openid_basic_headers(self, token: str) -> dict[str, str]:
        return self._kc_headers.openid_basic(basic_token=token)

    def openid_bearer_headers(self, token: str) -> dict[str, str]:
        return self._kc_headers.openid_bearer(bearer_token=token)

    def build_full_url(self, path: str, query: str = "") -> str:
        return self._kc_client.build_full_url(path=path, query=query)

    async def close_connection(self) -> None:
        await self._kc_client.client.aclose()
