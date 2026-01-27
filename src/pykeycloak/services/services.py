# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import asyncio
import math
from asyncio import Queue
from http import HTTPStatus
from uuid import UUID

from httpx import Response

from pykeycloak.core.aliases import JsonData
from pykeycloak.core.constants import KEYCLOAK_CONCURRENCY_LIMIT_DEFAULT
from pykeycloak.core.helpers import dataclass_from_dict
from pykeycloak.providers.payloads import (
    ClientCredentialsLoginPayload,
    CreateUserPayload,
    PermissionPayload,
    PermissionScopesPayload,
    RefreshTokenPayload,
    ResourcePayload,
    RolePayload,
    RolePolicyPayload,
    RTPIntrospectionPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
    UserCredentialsLoginPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
)
from pykeycloak.providers.providers import (
    KeycloakProviderProtocol,
)
from pykeycloak.providers.queries import (
    FilterFindPolicyParams,
    FindPermissionQuery,
    GetUsersQuery,
    PaginationQuery,
    ResourcesListQuery,
    RoleMembersListQuery,
)
from pykeycloak.services.representations import (
    AuthzSettingsRepresentation,
    ClientRepresentation,
    IntrospectRepresentation,
    PermissionRepresentation,
    PolicyRepresentation,
    ScopeRepresentation,
    SessionRepresentation,
    SessionsCountRepresentation,
    SessionsStatsRepresentation,
    TokenRepresentation,
    UserInfoRepresentation,
)


class BaseService:
    """ """

    def __init__(self, provider: KeycloakProviderProtocol):
        self._provider = provider

    @staticmethod
    def validate_response(response: Response) -> JsonData:
        if response.status_code == HTTPStatus.CREATED:
            return None

        if response.status_code == HTTPStatus.NO_CONTENT:
            return None

        if response.status_code == HTTPStatus.CONFLICT:
            """
            """
            return None

        if response.status_code == HTTPStatus.BAD_REQUEST:
            """
            """
            return None

        if response.status_code == HTTPStatus.SERVICE_UNAVAILABLE:
            """
            """
            return None

        if response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
            return None

        try:
            data = response.json()
        except Exception as e:
            raise ValueError(f"Failed to decode JSON response: {e}") from e

        if not isinstance(data, (dict, list)):
            raise TypeError(f"Expected JSON dict or list, got {type(data).__name__}")

        return data


class UsersService(BaseService):
    """ """

    async def get_user_async(self, user_id: UUID | str) -> JsonData:
        response = await self._provider.get_user_async(user_id=user_id)

        return self.validate_response(response)

    async def get_users_count_async(self, query: GetUsersQuery | None = None) -> int:
        response = await self._provider.get_users_count_async(query=query)

        return int(response.json())

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
        queue: Queue[GetUsersQuery] = asyncio.Queue()

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

        async def worker() -> None:
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
    ) -> JsonData:
        response = await self._provider.get_users_by_role_async(
            role_name=role_name, request_query=query
        )

        return self.validate_response(response)

    async def create_user_async(self, payload: CreateUserPayload) -> JsonData:
        response = await self._provider.create_user_async(payload=payload)

        return self.validate_response(response)

    async def update_user_async(
        self, user_id: UUID | str, payload: CreateUserPayload
    ) -> JsonData:
        response = await self._provider.update_user_by_id_async(
            user_id=user_id, payload=payload
        )

        return self.validate_response(response)

    async def enable_user_async(
        self, user_id: UUID | str, payload: UserUpdateEnablePayload
    ) -> JsonData:
        response = await self._provider.update_user_enable_by_id_async(
            user_id=user_id, payload=payload
        )

        return self.validate_response(response)

    async def update_user_password_async(
        self, user_id: UUID | str, payload: UserUpdatePasswordPayload
    ) -> JsonData:
        response = await self._provider.update_user_password_by_id_async(
            user_id=user_id, payload=payload
        )

        return self.validate_response(response)

    async def delete_user_async(self, user_id: UUID | str) -> JsonData:
        response = await self._provider.delete_user_async(user_id=user_id)

        return self.validate_response(response)


class RolesService(BaseService):
    """ """

    async def get_client_roles_raw_async(self) -> JsonData:
        response = await self._provider.get_client_roles_async()

        return self.validate_response(response)

    async def get_client_roles_async(self) -> JsonData:
        data = await self.get_client_roles_raw_async()

        return data

    async def get_role_id_async(self, role_name: str) -> JsonData:
        response = await self._provider.get_client_role_id_async(role_name=role_name)

        return self.validate_response(response)

    async def get_role_by_name_raw_async(self, role_name: str) -> JsonData:
        response = await self._provider.get_role_by_name_async(role_name=role_name)

        return self.validate_response(response)

    async def get_role_by_name_async(self, role_name: str) -> JsonData:
        data = await self.get_role_by_name_raw_async(role_name=role_name)

        return data

    async def create_role_raw_async(self, payload: RolePayload) -> JsonData:
        response = await self._provider.create_role_async(payload=payload)

        return self.validate_response(response)

    async def create_role_async(self, payload: RolePayload) -> JsonData:
        data = await self.create_role_raw_async(payload=payload)

        return data

    async def update_role_by_id_async(
        self,
        role_id: UUID,
        payload: RolePayload,
        skip_unexpected_behaviour_exception: bool = False,
    ) -> None:
        await self._provider.update_role_by_id_async(
            role_id=role_id,
            payload=payload,
            skip_unexpected_behaviour_exception=skip_unexpected_behaviour_exception,
        )

    async def delete_role_by_id_async(self, role_id: UUID) -> JsonData:
        response = await self._provider.delete_role_by_id_async(role_id=role_id)

        return self.validate_response(response)

    async def delete_role_by_name_async(self, role_name: str) -> JsonData:
        response = await self._provider.delete_role_by_name_async(role_name=role_name)

        return self.validate_response(response)

    async def update_role_by_name_raw_async(
        self, role_name: str, payload: RolePayload
    ) -> JsonData:
        response = await self._provider.update_role_by_name_async(
            role_name=role_name, payload=payload
        )

        return self.validate_response(response)

    async def update_role_by_name_async(
        self, role_name: str, payload: RolePayload
    ) -> JsonData:
        data = await self.update_role_by_name_raw_async(
            role_name=role_name, payload=payload
        )

        return data

    async def assign_client_role_async(
        self, user_id: UUID | str, roles: list[str]
    ) -> JsonData:
        response = await self._provider.assign_client_role_async(
            user_id=user_id, roles=roles
        )

        return self.validate_response(response)

    async def get_client_roles_of_user_async(self, user_id: UUID | str) -> JsonData:
        response = await self._provider.get_client_roles_of_user_async(user_id=user_id)

        return self.validate_response(response)

    async def get_composite_client_roles_of_user_async(
        self, user_id: UUID | str
    ) -> JsonData:
        response = await self._provider.get_composite_client_roles_of_user_async(
            user_id=user_id
        )

        return self.validate_response(response)

    async def get_available_client_roles_of_user_async(
        self, user_id: UUID | str
    ) -> JsonData:
        response = await self._provider.get_available_client_roles_of_user_async(
            user_id=user_id
        )

        return self.validate_response(response)

    async def delete_client_roles_of_user_async(
        self, user_id: UUID | str, roles: list[str]
    ) -> None:
        await self._provider.delete_client_roles_of_user_async(
            user_id=user_id,
            roles=roles,
        )

    async def get_user_roles_async(self, user_id: UUID | str) -> JsonData:
        response = await self._provider.get_user_roles_async(user_id=user_id)

        return self.validate_response(response)


class SessionsService(BaseService):
    async def get_client_sessions_raw_async(
        self, query: PaginationQuery | None = None
    ) -> JsonData:
        response = await self._provider.get_client_sessions_async(query=query)
        return self.validate_response(response)

    async def get_client_sessions_async(
        self,
        query: PaginationQuery | None = None,
    ) -> list[SessionRepresentation]:
        data = await self.get_client_sessions_raw_async(query=query)

        return dataclass_from_dict(data, list[SessionRepresentation])

    async def get_user_sessions_raw_async(
        self,
        user_id: UUID | str,
    ) -> JsonData:
        response = await self._provider.get_user_sessions_async(user_id=user_id)
        return self.validate_response(response)

    async def get_user_sessions_async(
        self,
        user_id: UUID | str,
    ) -> list[SessionRepresentation]:
        data = await self.get_user_sessions_raw_async(user_id=user_id)

        return dataclass_from_dict(data, list[SessionRepresentation])

    async def get_client_sessions_count_raw_async(self) -> JsonData:
        response = await self._provider.get_client_sessions_count_async()
        return self.validate_response(response)

    async def get_client_sessions_count_async(
        self,
    ) -> SessionsCountRepresentation:
        data = await self.get_client_sessions_count_raw_async()

        return dataclass_from_dict(data, SessionsCountRepresentation)

    async def get_offline_sessions_raw_async(
        self,
        query: PaginationQuery | None = None,
    ) -> JsonData:
        response = await self._provider.get_offline_sessions_async(query=query)
        return self.validate_response(response)

    async def get_offline_sessions_async(
        self,
        query: PaginationQuery | None = None,
    ) -> list[SessionRepresentation]:
        data = await self.get_offline_sessions_raw_async(query=query)

        return dataclass_from_dict(data, list[SessionRepresentation])

    async def get_offline_sessions_count_raw_async(self) -> JsonData:
        response = await self._provider.get_offline_sessions_count_async()
        return self.validate_response(response)

    async def get_offline_sessions_count_async(
        self,
    ) -> SessionsCountRepresentation:
        data = await self.get_offline_sessions_count_raw_async()

        return dataclass_from_dict(data, SessionsCountRepresentation)

    async def remove_user_sessions_raw_async(
        self,
        user_id: UUID | str,
    ) -> JsonData:
        response = await self._provider.remove_user_sessions_async(user_id=user_id)
        return self.validate_response(response)

    async def logout_all_users_raw_async(self) -> JsonData:
        response = await self._provider.logout_all_users_async()
        return self.validate_response(response)

    async def logout_all_users_async(self) -> None:
        await self.logout_all_users_raw_async()

    async def get_client_session_stats_raw_async(
        self,
    ) -> JsonData:
        response = await self._provider.get_client_session_stats_async()
        return self.validate_response(response)

    async def get_client_session_stats_async(
        self,
    ) -> list[SessionsStatsRepresentation]:
        data = await self.get_client_session_stats_raw_async()

        return dataclass_from_dict(data, list[SessionsStatsRepresentation])

    async def get_client_user_offline_sessions_raw_async(
        self,
        user_id: UUID | str,
    ) -> JsonData:
        response = await self._provider.get_client_user_offline_sessions_async(
            user_id=user_id
        )
        return self.validate_response(response)

    async def get_client_user_offline_sessions_async(
        self,
        user_id: UUID | str,
    ) -> SessionRepresentation:
        data = await self.get_client_user_offline_sessions_raw_async(user_id=user_id)

        return dataclass_from_dict(data, SessionRepresentation)

    async def delete_session_by_id_async(
        self, session_id: UUID | str, is_offline: bool
    ) -> JsonData:
        response = await self._provider.delete_session_by_id_async(
            session_id=session_id, is_offline=is_offline
        )

        return self.validate_response(response)


class AuthService(BaseService):
    ###
    # Client Login
    ###

    async def client_login_raw_async(
        self,
    ) -> JsonData:
        response = await self._provider.obtain_token_async(
            payload=ClientCredentialsLoginPayload()
        )

        return self.validate_response(response)

    async def client_login_async(
        self,
    ) -> TokenRepresentation:
        data = await self.client_login_raw_async()

        return dataclass_from_dict(data, TokenRepresentation)

    ###
    # User Login
    ###

    async def user_login_raw_async(
        self,
        payload: UserCredentialsLoginPayload,
    ) -> JsonData:
        response = await self._provider.obtain_token_async(payload=payload)

        return self.validate_response(response)

    async def user_login_async(
        self,
        payload: UserCredentialsLoginPayload,
    ) -> TokenRepresentation:
        data = await self.user_login_raw_async(payload=payload)

        return dataclass_from_dict(data, TokenRepresentation)

    ###
    # General token operations
    ###

    async def obtain_token_raw_async(
        self,
        *,
        payload: ClientCredentialsLoginPayload | UserCredentialsLoginPayload,
    ) -> JsonData:
        response = await self._provider.obtain_token_async(payload=payload)

        return self.validate_response(response)

    async def obtain_token_async(
        self,
        *,
        payload: ClientCredentialsLoginPayload | UserCredentialsLoginPayload,
    ) -> TokenRepresentation:
        data = await self.obtain_token_raw_async(payload=payload)

        return dataclass_from_dict(data, TokenRepresentation)

    ###
    # Refresh token
    ###

    async def refresh_token_raw_async(
        self,
        payload: RefreshTokenPayload,
    ) -> JsonData:
        response = await self._provider.refresh_token_async(payload=payload)

        return self.validate_response(response)

    async def refresh_token_async(
        self,
        payload: RefreshTokenPayload,
    ) -> TokenRepresentation:
        data = await self.refresh_token_raw_async(payload=payload)

        return dataclass_from_dict(data, TokenRepresentation)

    ###
    # User info
    ###

    async def get_user_info_raw_async(
        self,
        access_token: str,
    ) -> JsonData:
        response = await self._provider.get_user_info_async(access_token)

        return self.validate_response(response)

    async def get_user_info_async(
        self,
        access_token: str,
    ) -> UserInfoRepresentation:
        data = await self.get_user_info_raw_async(access_token)

        return dataclass_from_dict(data, UserInfoRepresentation)

    ###
    # Logout
    ###

    async def logout_raw_async(self, refresh_token: str) -> JsonData:
        response = await self._provider.logout_async(refresh_token=refresh_token)

        return self.validate_response(response)

    async def logout_async(self, refresh_token: str) -> None:
        response = await self._provider.logout_async(refresh_token=refresh_token)

        if response.status_code != HTTPStatus.NO_CONTENT:
            raise ValueError("Unexpected response from Keycloak")

    ###
    # Introspect
    ###

    async def introspect_token_raw_async(
        self,
        payload: RTPIntrospectionPayload | TokenIntrospectionPayload,
    ) -> JsonData:
        response = await self._provider.introspect_token_async(payload=payload)

        return self.validate_response(response)

    async def introspect_token_async(
        self,
        payload: RTPIntrospectionPayload | TokenIntrospectionPayload,
    ) -> IntrospectRepresentation:
        data = await self.introspect_token_raw_async(payload=payload)

        return dataclass_from_dict(data, IntrospectRepresentation)

    ###
    # Auth Device
    ###

    async def auth_device_raw_async(
        self,
        access_token: str,
    ) -> JsonData:
        response = await self._provider.auth_device_async(access_token=access_token)

        return self.validate_response(response)

    async def auth_device_async(
        self,
        access_token: str,
    ) -> JsonData:
        response = await self._provider.auth_device_async(access_token=access_token)

        return self.validate_response(response)

    ###
    # Certs
    ###

    async def get_certs_raw_async(
        self,
        access_token: str,
    ) -> JsonData:
        response = await self._provider.get_certs_async(access_token=access_token)

        return self.validate_response(response)

    async def get_certs_async(
        self,
        access_token: str,
    ) -> JsonData:
        response = await self._provider.get_certs_async(access_token=access_token)

        return self.validate_response(response)

    ###
    # Revoke
    ###

    async def revoke_raw_async(
        self,
        refresh_token: str,
    ) -> JsonData:
        response = await self._provider.revoke_async(refresh_token=refresh_token)

        return self.validate_response(response)

    async def revoke_async(
        self,
        refresh_token: str,
    ) -> None:
        response = await self._provider.revoke_async(refresh_token=refresh_token)

        if response.status_code != HTTPStatus.NO_CONTENT:
            raise ValueError("Unexpected response from Keycloak")

    ###
    # UMA Permissions
    ###

    async def get_uma_permission_async(
        self,
        payload: UMAAuthorizationPayload,
    ) -> JsonData:
        data = await self.get_uma_permission_async(payload=payload)

        return data


class UmaService(BaseService):
    async def get_uma_permissions_async(
        self, payload: UMAAuthorizationPayload
    ) -> JsonData:
        response = await self._provider.get_uma_permission_async(payload=payload)

        return self.validate_response(response)


class ClientsService(BaseService):
    async def get_client_raw_async(self) -> JsonData:
        response = await self._provider.get_client_async()

        return self.validate_response(response)

    async def get_client_async(
        self,
    ) -> ClientRepresentation:
        data = await self.get_client_raw_async()

        from pykeycloak.core.helpers import dataclass_from_dict

        return dataclass_from_dict(data, ClientRepresentation)

    async def get_clients_raw_async(self) -> JsonData:
        response = await self._provider.get_clients_async()

        return self.validate_response(response)

    async def get_clients_async(
        self,
    ) -> list[ClientRepresentation]:
        data = await self.get_clients_raw_async()

        from pykeycloak.core.helpers import dataclass_from_dict

        return dataclass_from_dict(data, list[ClientRepresentation])


class AuthzService(BaseService):
    async def get_client_authz_settings_raw_async(self) -> JsonData:
        response = await self._provider.get_client_authz_settings()

        return self.validate_response(response)

    async def get_client_authz_settings_async(
        self,
    ) -> AuthzSettingsRepresentation:
        data = await self.get_client_authz_settings_raw_async()

        return dataclass_from_dict(data, AuthzSettingsRepresentation)


class AuthzResourceService(BaseService):
    async def get_resources_raw_async(
        self, query: ResourcesListQuery | None = None
    ) -> JsonData:
        response = await self._provider.get_resources_async(query=query)

        return self.validate_response(response)

    async def get_resources_async(
        self, query: ResourcesListQuery | None = None
    ) -> JsonData:
        data = await self.get_resources_raw_async(query=query)

        return data

    async def create_resource_async(self, payload: ResourcePayload) -> JsonData:
        response = await self._provider.create_resource_async(payload=payload)

        return self.validate_response(response)

    async def get_resource_by_id_raw_async(self, resource_id: str) -> JsonData:
        response = await self._provider.get_resource_by_id_async(
            resource_id=resource_id
        )

        return self.validate_response(response)

    async def get_resource_by_id_async(self, resource_id: str) -> JsonData:
        data = await self.get_resource_by_id_raw_async(resource_id=resource_id)

        return data

    async def delete_resource_by_id_async(self, resource_id: str) -> JsonData:
        response = await self._provider.delete_resource_by_id_async(
            resource_id=resource_id
        )

        return self.validate_response(response)

    async def get_resource_permissions_async(self, resource_id: str) -> JsonData:
        response = await self._provider.get_resource_permissions_async(
            resource_id=resource_id
        )

        return self.validate_response(response)


class AuthzScopeService(BaseService):
    async def get_client_authz_scopes_raw_async(self) -> JsonData:
        response = await self._provider.get_client_authz_scopes_async()

        return self.validate_response(response)

    async def get_client_authz_scopes_async(self) -> list[ScopeRepresentation]:
        data = await self.get_client_authz_scopes_raw_async()

        return dataclass_from_dict(data, list[ScopeRepresentation])


class AuthzPermissionService(BaseService):
    async def create_client_authz_permission_resource_based_async(
        self, payload: PermissionPayload
    ) -> JsonData:
        response = (
            await self._provider.create_client_authz_permission_resource_based_async(
                payload=payload
            )
        )

        return self.validate_response(response)

    async def create_client_authz_permission_scope_based_async(
        self, payload: PermissionPayload
    ) -> JsonData:
        response = (
            await self._provider.create_client_authz_permission_scope_based_async(
                payload=payload
            )
        )

        return self.validate_response(response)

    async def get_permissions_raw_async(
        self, query: FindPermissionQuery | None = None
    ) -> JsonData:
        response = await self._provider.get_permissions_async(query=query)

        return self.validate_response(response)

    async def get_permissions_async(
        self, query: FindPermissionQuery | None = None
    ) -> list[PermissionRepresentation]:
        data = await self.get_permissions_raw_async(query=query)

        return dataclass_from_dict(data, list[PermissionRepresentation])

    async def get_permissions_for_scope_by_id_async(
        self, permission_id: str
    ) -> JsonData:
        """?! не понимаю что этот метод делает"""
        response = await self._provider.get_permissions_for_scope_by_id_async(
            permission_id=permission_id
        )

        return self.validate_response(response)

    async def delete_permission_async(self, permission_id: str) -> JsonData:
        response = await self._provider.delete_permission_async(
            permission_id=permission_id
        )

        return self.validate_response(response)

    async def update_permission_scopes_async(
        self,
        permission_id: str,  # resource OR scope based permission
        payload: PermissionScopesPayload,
    ) -> JsonData:
        response = await self._provider.update_permission_scopes_async(
            permission_id=permission_id, payload=payload
        )

        return self.validate_response(response)


class AuthPolicyService(BaseService):
    async def get_policy_associated_role_policies_raw_async(
        self, policy_id: str
    ) -> JsonData:
        response = await self._provider.get_policy_associated_role_policies_async(
            policy_id=policy_id
        )

        return self.validate_response(response)

    async def get_policy_associated_role_policies_async(
        self, policy_id: str
    ) -> list[PolicyRepresentation]:
        data = await self.get_policy_associated_role_policies_raw_async(
            policy_id=policy_id
        )

        return dataclass_from_dict(data, list[PolicyRepresentation])

    async def create_policy_role_async(self, payload: RolePolicyPayload) -> JsonData:
        response = await self._provider.create_policy_role_async(payload=payload)

        return self.validate_response(response)

    async def delete_policy_async(self, policy_id: str) -> JsonData:
        response = await self._provider.delete_policy_async(policy_id=policy_id)

        return self.validate_response(response)

    async def create_policy_async(self, payload: PermissionPayload) -> JsonData:
        response = await self._provider.create_policy_async(payload=payload)

        return self.validate_response(response)

    async def get_policy_by_name_raw_async(
        self, query: FilterFindPolicyParams | None = None
    ) -> JsonData:
        response = await self._provider.get_policy_by_name_async(query=query)

        return self.validate_response(response)

    async def get_policy_by_name_async(
        self, query: FilterFindPolicyParams | None = None
    ) -> JsonData:
        data = await self.get_policy_by_name_raw_async(query=query)

        return data

    async def get_associated_policies_async(self, policy_id: str) -> JsonData:
        response = await self._provider.get_associated_policies_async(
            policy_id=policy_id
        )

        return self.validate_response(response)

    async def get_policy_authorisation_scopes_async(
        self, permission_id: str
    ) -> JsonData:
        response = await self._provider.get_policy_authorisation_scopes_async(
            permission_id=permission_id
        )

        return self.validate_response(response)

    async def get_policies_raw_async(self) -> JsonData:
        response = await self._provider.get_policies_async()

        return self.validate_response(response)

    async def get_policies_async(self) -> JsonData:
        data = await self.get_policies_raw_async()

        return data
