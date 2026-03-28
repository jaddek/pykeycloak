# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from collections.abc import Awaitable, Callable
from uuid import UUID

from pykeycloak.core.clients import HttpMethod
from pykeycloak.core.protocols import KeycloakResponseProtocol
from pykeycloak.core.urls import (
    REALM_CLIENT_ACTIVE_SESSION_COUNT,
    REALM_CLIENT_OFFLINE_SESSION_COUNT,
    REALM_CLIENT_OFFLINE_SESSIONS,
    REALM_CLIENT_SESSION_STATS,
    REALM_CLIENT_USER_OFFLINE_SESSIONS,
    REALM_CLIENT_USER_SESSIONS,
    REALM_DELETE_SESSION,
    REALM_LOGOUT_ALL,
    REALM_USER_LOGOUT,
    REALM_USER_SESSIONS,
)

from ._base import KeycloakProviderBase
from .queries import PaginationQuery


class SessionsProvider:
    def __init__(
        self,
        base: KeycloakProviderBase,
        get_access_token: Callable[[], Awaitable[str]],
    ) -> None:
        self._base = base
        self._get_access_token = get_access_token

    async def get_client_sessions_async(
        self,
        query: PaginationQuery | None = None,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_USER_SESSIONS, id=self._base.realm_client.client_uuid
            ),
            headers=self._base.bearer_headers(access_token),
            params=query.to_dict() if query else None,
        )

    async def get_user_sessions_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_USER_SESSIONS, user_id=user_id),
            headers=self._base.bearer_headers(access_token),
        )

    async def delete_session_by_id_async(
        self,
        session_id: UUID | str,
        is_offline: bool,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.DELETE,
            url=self._base.build_url(path=REALM_DELETE_SESSION, session_id=session_id),
            headers=self._base.bearer_headers(access_token),
            params={"isOffline": "true" if is_offline else "false"},
        )

    async def get_client_user_sessions_async(
        self,
        request_query: PaginationQuery | None = None,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_USER_SESSIONS),
            headers=self._base.bearer_headers(access_token),
            params=request_query,
        )

    async def get_client_sessions_count_async(self) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_ACTIVE_SESSION_COUNT),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_offline_sessions_async(
        self,
        query: PaginationQuery | None = None,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_OFFLINE_SESSIONS),
            headers=self._base.bearer_headers(access_token),
            params=query.to_dict() if query else None,
        )

    async def get_offline_sessions_count_async(self) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_OFFLINE_SESSION_COUNT),
            headers=self._base.bearer_headers(access_token),
        )

    async def remove_user_sessions_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_USER_LOGOUT, user_id=user_id),
            headers=self._base.bearer_headers(access_token),
        )

    async def logout_all_users_async(self) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_LOGOUT_ALL),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_client_session_stats_async(self) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_SESSION_STATS),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_client_user_offline_sessions_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_USER_OFFLINE_SESSIONS, user_id=user_id
            ),
            headers=self._base.bearer_headers(access_token),
        )
