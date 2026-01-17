from http import HTTPStatus
from typing import Any

from httpx import Response

from pykeycloak.core.helpers import dataclass_from_dict
from pykeycloak.providers.payloads import (
    ClientCredentialsLoginPayload,
    RefreshTokenPayload,
    RTPIntrospectionPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
    UserCredentialsLoginPayload,
)
from pykeycloak.providers.providers import KeycloakProviderAsync
from pykeycloak.providers.queries import GetUsersQuery
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
    def validate_response(response: Response) -> dict[str, Any]:
        data = response.json()
        if not isinstance(data, dict):
            raise TypeError(f"Expected JSON object, got {type(data).__name__}")
        return data


class UsersService(BaseService):
    def get_user(self, user_id: str) -> dict[str, Any]:
        ...

    async def get_users_async(
            self,
            query: GetUsersQuery | None = None,
    ) -> list[Response]:
        users_count_response = await self._provider.get_users_count_async(query=query)

        try:
            users_count = int(users_count_response.text)
        except ValueError as e:
            raise RuntimeError("Invalid users count response") from e

        return await self.get_paginated_users_async(
            users_count=int(users_count),
            query=query
        )

    async def get_paginated_users_async(
            self,
            users_count: int,
            query: GetUsersQuery | None = None,
    ) -> list[Response]:
        _query = query or GetUsersQuery(max=DEFAULT_PAGE_SIZE)

        total_pages = math.ceil(users_count / query.max)
        concurrency_limit = 10
        queue = asyncio.Queue()

        if users_count <= _query.max:
            response = await self._wrapper.request(
                method="GET",
                url=self._get_path(path=REALM_USERS),
                headers=self._headers,
                query=_query,
            )
            return [response]

        for page in range(total_pages):
            first = page * query.max
            remaining = users_count - first
            current_max = min(query.max, remaining)
            page_query = GetUsersQuery(first=first, max=current_max, search=query.search)
            queue.put_nowait(page_query)

        responses: list[Response] = []

        async def worker():
            while not queue.empty():
                page_query = await queue.get()
                try:
                    resp = await self._wrapper.request(
                        method="GET",
                        url=self._get_path(path=REALM_USERS),
                        headers=self._headers,
                        query=page_query,
                    )
                    responses.append(resp)
                finally:
                    queue.task_done()

        async with asyncio.TaskGroup() as tg:
            for _ in range(concurrency_limit):
                tg.create_task(worker())

        return responses

    def get_users_by_role(self):
        ...

    def create_user(self):
        ...

    def update_user(self, user_id: str):
        ...

    def delete_user(self, user_id: str):
        ...


class RolesService(BaseService):
    async def get_public_roles(self):
        ...

    async def get_role_by_id(self):
        ...

    async def update_role_by_id(self):
        ...

    async def delete_client_role(self):
        ...

    async def deep_role_copy(self):
        ...


class SessionsService(BaseService):
    async def get_user_sessions(self):
        ...

    async def get_sessions(self):
        ...

    async def delete_session_by_id(self):
        ...

    async def delete_user_sessions(self):
        ...

    async def delete_all_sessions(self):
        ...

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
        self, payload: UMAAuthorizationPayload, access_token: str
    ) -> dict[str, Any]:
        response = await self._provider.get_uma_permission_async(
            payload=payload, access_token=access_token
        )

        return self.validate_response(response)
