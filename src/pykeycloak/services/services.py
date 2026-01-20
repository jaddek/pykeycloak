# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import asyncio
import math
from http import HTTPStatus
from typing import Any
from uuid import UUID

from httpx import Response

from pykeycloak.core.aliases import JsonData
from pykeycloak.core.constants import KEYCLOAK_CONCURRENCY_LIMIT_DEFAULT
from pykeycloak.core.helpers import dataclass_from_dict
from pykeycloak.providers.payloads import (
    ClientCredentialsLoginPayload,
    CreateUserPayload,
    RefreshTokenPayload,
    RTPIntrospectionPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
    UserCredentialsLoginPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
)
from pykeycloak.providers.providers import KeycloakProviderAsync
from pykeycloak.providers.queries import GetUsersQuery, RoleMembersListQuery
from pykeycloak.services.representations import (
    IntrospectRepresentation,
    R,
    TokenRepresentation,
    UserInfoRepresentation,
)


class BaseService:
    def __init__(self, provider: KeycloakProviderAsync):
        self._provider = provider

    @staticmethod
    def validate_response(response: Response) -> JsonData:
        try:
            data = response.json()
        except Exception as e:
            raise ValueError(f"Failed to decode JSON response: {e}") from e

        if not isinstance(data, (dict, list)):
            raise TypeError(f"Expected JSON dict or list, got {type(data).__name__}")

        return data


class UsersService(BaseService):
    async def get_user_async(self, user_id: UUID) -> dict[str, Any]:
        response = await self._provider.get_user_async(user_id=user_id)

        return response.json()

    async def get_users_count(self, query: GetUsersQuery | None = None) -> int:
        response = await self._provider.get_users_count_async(query=query)

        return response.json()

    async def get_users_async(
        self,
        query: GetUsersQuery | None = None,
    ) -> list[JsonData]:
        users_count_response = await self._provider.get_users_count_async(query=query)

        try:
            users_count_text = users_count_response.text.strip()
            if not users_count_text.isdigit():
                raise RuntimeError("Invalid users count response: not a number")
            users_count = int(users_count_text)
        except ValueError as e:
            raise RuntimeError("Invalid users count response") from e

        return await self.get_paginated_users_async(
            users_count=int(users_count), query=query
        )

    async def get_paginated_users_async(
        self,
        users_count: int,
        concurrency_limit: int = KEYCLOAK_CONCURRENCY_LIMIT_DEFAULT,
        query: GetUsersQuery | None = None,
    ) -> list[JsonData]:
        _query = query or GetUsersQuery()

        total_pages = math.ceil(users_count / _query.max)
        queue = asyncio.Queue()

        if users_count <= _query.max:
            response = await self._provider.get_users_async(query=_query)

            data = response.json()

            return [data]

        for page in range(total_pages):
            first = page * _query.max
            remaining = users_count - first
            current_max = min(_query.max, remaining)
            page_query = GetUsersQuery(
                first=first, max=current_max, search=_query.search
            )
            queue.put_nowait(page_query)

        responses: list[JsonData] = []

        async def worker():
            while True:
                try:
                    worker_page_query = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                try:
                    worker_page_response = await self._provider.get_users_async(
                        query=worker_page_query
                    )
                    responses.append(worker_page_response.json())
                finally:
                    queue.task_done()

        async with asyncio.TaskGroup() as tg:
            for _ in range(min(concurrency_limit, total_pages)):
                tg.create_task(worker())

        return responses

    async def get_users_by_role_async(
        self, role_name: str, query: RoleMembersListQuery | None = None
    ) -> list[JsonData]:
        response = await self._provider.get_users_by_role_async(
            role_name=role_name, query=query
        )

        return response.json()

    async def create_user_async(self, payload: CreateUserPayload) -> JsonData:
        response = await self._provider.create_user_async(parent=payload)

        return response.json()

    async def update_user_async(
        self, user_id: UUID, payload: CreateUserPayload
    ) -> JsonData:
        response = await self._provider.update_user_by_id_async(
            user_id=user_id, payload=payload
        )

        return response.json()

    async def enable_user_async(
        self, user_id: UUID, payload: UserUpdateEnablePayload
    ) -> JsonData:
        response = await self._provider.update_user_enable_by_id_async(
            user_id=user_id, payload=payload
        )

        return response.json()

    async def update_user_password_async(
        self, user_id: UUID, payload: UserUpdatePasswordPayload
    ) -> JsonData:
        response = await self._provider.update_user_password_by_id_async(
            user_id=user_id, payload=payload
        )

        return response.json()

    async def delete_user_async(self, user_id: UUID):
        response = await self._provider.delete_user_async(user_id=user_id)

        return response.json()


class RolesService(BaseService):
    async def get_public_roles(self): ...

    async def get_role_by_id(self): ...

    async def update_role_by_id(self): ...

    async def delete_client_role(self): ...

    async def deep_role_copy(self): ...


class SessionsService(BaseService):
    async def get_user_sessions(self): ...

    async def get_sessions(self): ...

    async def delete_session_by_id(self): ...

    async def delete_user_sessions(self): ...

    async def delete_all_sessions(self): ...


class AuthService(BaseService):

    ###
    # Client Login
    ###

    async def client_login_raw_async(
        self,
    ) -> dict[str, Any]:
        response = await self._provider.obtain_token_async(
            payload=ClientCredentialsLoginPayload()
        )

        return self.validate_response(response)

    async def client_login_async(
        self,
        transform_to_response_model: type[R] = TokenRepresentation,  # type: ignore
    ) -> R:
        data = await self.client_login_raw_async()

        return dataclass_from_dict(data, transform_to_response_model)

    ###
    # User Login
    ###

    async def user_login_raw_async(
        self,
        payload: UserCredentialsLoginPayload,
    ) -> dict[str, Any]:
        response = await self._provider.obtain_token_async(payload=payload)

        return self.validate_response(response)

    async def user_login_async(
        self,
        payload: UserCredentialsLoginPayload,
        transform_to_response_model: type[R] = TokenRepresentation,  # type: ignore
    ) -> R:
        data = await self.user_login_raw_async(payload=payload)

        return dataclass_from_dict(data, transform_to_response_model)

    ###
    # Refresh token
    ###

    async def refresh_token_raw_async(
        self,
        payload: RefreshTokenPayload,
    ) -> dict[str, Any]:
        response = await self._provider.refresh_token_async(payload=payload)

        return self.validate_response(response)

    async def refresh_token_async(
        self,
        payload: RefreshTokenPayload,
        transform_to_response_model: type[R] = TokenRepresentation,  # type: ignore
    ) -> R:
        data = await self.refresh_token_raw_async(payload=payload)

        return dataclass_from_dict(data, transform_to_response_model)

    ###
    # User info
    ###

    async def get_user_info_raw_async(
        self,
        access_token: str,
    ) -> dict[str, Any]:
        response = await self._provider.get_user_info_async(access_token)

        return self.validate_response(response)

    async def get_user_info_async(
        self,
        access_token: str,
        transform_to_response_model: type[R] = UserInfoRepresentation,  # type: ignore
    ) -> R:
        data = await self.get_user_info_raw_async(access_token)

        return dataclass_from_dict(data, transform_to_response_model)

    ###
    # Logout
    ###

    async def logout_async(self, refresh_token: str) -> None:
        response = await self._provider.logout_async(refresh_token)

        if response.status_code != HTTPStatus.NO_CONTENT:
            raise ValueError("Unexpected response from Keycloak")

    ###
    # Introspect
    ###

    async def introspect_raw_async(
        self,
        payload: RTPIntrospectionPayload | TokenIntrospectionPayload,
    ) -> dict[str, Any]:
        response = await self._provider.introspect_token_async(payload=payload)

        return self.validate_response(response)

    async def introspect_async(
        self,
        payload: RTPIntrospectionPayload | TokenIntrospectionPayload,
        transform_to_response_model: type[R] = IntrospectRepresentation,  # type: ignore
    ) -> R:
        data = await self.introspect_raw_async(payload=payload)

        return dataclass_from_dict(data, transform_to_response_model)

    ###
    # Auth Device
    ###

    async def auth_device_raw_async(
        self,
    ) -> dict[str, Any]:
        response = await self._provider.auth_device_async()

        return self.validate_response(response)

    ###
    # Certs
    ###

    async def get_certs_raw_async(
        self,
    ) -> dict[str, Any]:
        response = await self._provider.get_certs_async()

        return self.validate_response(response)


class UmaService(BaseService):
    async def get_uma_permissions_async(
        self, payload: UMAAuthorizationPayload
    ) -> dict[str, Any]:
        response = await self._provider.get_uma_permission_async(payload=payload)

        return self.validate_response(response)
