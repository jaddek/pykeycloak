# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from collections.abc import Awaitable, Callable
from uuid import UUID

from pykeycloak.core.clients import HttpMethod
from pykeycloak.core.protocols import KeycloakResponseProtocol
from pykeycloak.core.urls import (
    REALM_CLIENT_ROLE_MEMBERS,
    REALM_USER,
    REALM_USER_IMPERSONATION,
    REALM_USERS_COUNT,
    REALM_USERS_LIST,
)

from ._base import KeycloakProviderBase
from .payloads import (
    CreateUserPayload,
    UpdateUserPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
)
from .queries import GetUsersQuery, RoleMembersListQuery


class UsersProvider:
    def __init__(
        self,
        base: KeycloakProviderBase,
        get_access_token: Callable[[], Awaitable[str]],
    ) -> None:
        self._base = base
        self._get_access_token = get_access_token

    async def get_users_count_async(
        self,
        query: GetUsersQuery | None = None,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_USERS_COUNT),
            headers=self._base.bearer_headers(access_token),
            params=query.to_dict() if query else None,
        )

    async def get_users_async(
        self,
        query: GetUsersQuery | None = None,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_USERS_LIST),
            headers=self._base.bearer_headers(access_token),
            params=query or GetUsersQuery(),
        )

    async def get_user_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_USER, user_id=user_id),
            headers=self._base.bearer_headers(access_token),
        )

    async def delete_user_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.DELETE,
            url=self._base.build_url(path=REALM_USER, user_id=user_id),
            headers=self._base.bearer_headers(access_token),
        )

    async def create_user_async(
        self,
        payload: CreateUserPayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_USERS_LIST),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_json(),
        )

    async def update_user_by_id_async(
        self,
        user_id: UUID | str,
        payload: UpdateUserPayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.PUT,
            url=self._base.build_url(path=REALM_USER, user_id=user_id),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_json(),
        )

    async def update_user_enable_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdateEnablePayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.PUT,
            url=self._base.build_url(path=REALM_USER, user_id=user_id),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_json(),
        )

    async def update_user_password_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdatePasswordPayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.PUT,
            url=self._base.build_url(path=REALM_USER, user_id=user_id),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_json(),
        )

    async def get_users_by_role_async(
        self,
        role_name: str,
        request_query: RoleMembersListQuery | None = None,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_ROLE_MEMBERS, role_name=role_name
            ),
            headers=self._base.bearer_headers(access_token),
            params=request_query if request_query else {},
        )

    async def impersonate_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_USER_IMPERSONATION, user_id=user_id),
            headers=self._base.bearer_headers(access_token),
        )
