# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from collections.abc import Awaitable, Callable

from pykeycloak.core.clients import HttpMethod
from pykeycloak.core.protocols import KeycloakResponseProtocol
from pykeycloak.core.urls import REALM_CLIENT, REALM_CLIENTS

from ._base import KeycloakProviderBase


class ClientsProvider:
    def __init__(
        self,
        base: KeycloakProviderBase,
        get_access_token: Callable[[], Awaitable[str]],
    ) -> None:
        self._base = base
        self._get_access_token = get_access_token

    async def get_clients_async(self) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENTS),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_client_async(self) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT),
            headers=self._base.bearer_headers(access_token),
        )
