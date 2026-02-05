# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import asyncio
import math
from collections.abc import Iterable
from typing import cast
from uuid import UUID

from ..core.constants import KEYCLOAK_CONCURRENCY_LIMIT_DEFAULT
from ..core.exceptions import KeycloakException
from ..core.helpers import dataclass_from_dict
from ..core.protocols import (
    KeycloakProviderProtocol,
    KeycloakResponseValidatorProtocol,
    ResponseProtocol,
)
from ..core.types import JsonData
from ..providers.payloads import (
    ClientCredentialsLoginPayload,
    CreateUserPayload,
    PermissionPayload,
    PermissionScopesPayload,
    RefreshTokenPayload,
    ResourcePayload,
    RoleAssignPayload,
    RolePayload,
    RolePolicyPayload,
    RTPIntrospectionPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
    UpdateUserPayload,
    UserCredentialsLoginPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
)
from ..providers.queries import (
    FilterFindPolicyParams,
    FindPermissionQuery,
    GetUsersQuery,
    PaginationQuery,
    ResourcesListQuery,
    RoleMembersListQuery,
)
from ..services.representations import (
    AuthzSettingsRepresentation,
    ClientRepresentation,
    DeviceAuthRepresentation,
    IntrospectRepresentation,
    PermissionRepresentation,
    PolicyRepresentation,
    ScopeRepresentation,
    SessionRepresentation,
    SessionsCountRepresentation,
    SessionsStatsRepresentation,
    TokenRepresentation,
    UserInfoRepresentation,
    UserRepresentation,
)


class BaseService:
    """ """

    def __init__(
        self,
        provider: KeycloakProviderProtocol,
        validator: KeycloakResponseValidatorProtocol,
    ):
        self._provider = provider
        self._validator = validator

    def validate_response(self, response: ResponseProtocol) -> JsonData:
        return self._validator.validate(response)


class UsersService(BaseService):
    """ """

    async def get_user_raw_async(self, user_id: UUID | str) -> JsonData:
        response = await self._provider.get_user_async(user_id=user_id)

        return self.validate_response(response)

    async def get_user_async(self, user_id: UUID | str) -> UserRepresentation:
        data = await self.get_user_raw_async(user_id=user_id)

        return dataclass_from_dict(data, UserRepresentation)

    async def get_users_count_async(self, query: GetUsersQuery | None = None) -> int:
        response = await self._provider.get_users_count_async(query=query)

        data = response.json()

        if isinstance(data, (str, int, float)):
            return int(data)

        raise ValueError(f"Expected numeric data from Keycloak, got {type(data)}")

    async def get_users_raw_async(
        self,
        query: GetUsersQuery | None = None,
    ) -> tuple[list[JsonData], int]:
        users_count_response = await self._provider.get_users_count_async(query=query)
        users_count = limit = int(users_count_response.text.strip())

        responses = await self.get_paginated_users_async(users_count=limit, query=query)

        return [
            item
            for r in responses
            for item in cast(Iterable[JsonData], self.validate_response(r))
        ], users_count

    async def get_users_async(
        self,
        query: GetUsersQuery | None = None,
    ) -> tuple[list[UserRepresentation], int]:
        data, users_count = await self.get_users_raw_async(query=query)

        return dataclass_from_dict(data, list[UserRepresentation]), users_count

    async def get_all_users_async(
        self,
    ) -> tuple[list[UserRepresentation], int]:
        query = GetUsersQuery(find_all=True)
        data, users_count = await self.get_users_raw_async(query=query)

        return dataclass_from_dict(data, list[UserRepresentation]), users_count

    async def get_paginated_users_async(
        self,
        users_count: int,
        concurrency_limit: int = KEYCLOAK_CONCURRENCY_LIMIT_DEFAULT,
        query: GetUsersQuery | None = None,
    ) -> list[ResponseProtocol]:
        _query = query or GetUsersQuery()

        total_pages: int = 1

        if _query.find_all:
            total_pages = math.ceil(users_count / _query.max)

        semaphore = asyncio.Semaphore(concurrency_limit)

        async def fetch_page(first_raw: int, current_max_rows: int) -> ResponseProtocol:
            page_query = GetUsersQuery(
                first=first_raw, max=current_max_rows, search=_query.search
            )
            async with semaphore:
                return await self._provider.get_users_async(query=page_query)

        tasks = []
        for page in range(total_pages):
            current_first = _query.first + (page * _query.max)

            tasks.append(fetch_page(current_first, _query.max))

        return await asyncio.gather(*tasks)

    async def get_users_by_role_async(
        self, role_name: str, query: RoleMembersListQuery | None = None
    ) -> JsonData:
        response = await self._provider.get_users_by_role_async(
            role_name=role_name, request_query=query
        )

        return self.validate_response(response)

    async def create_user_async(self, payload: CreateUserPayload) -> str:
        response = await self._provider.create_user_async(payload=payload)

        self.validate_response(response)

        if not response.headers:
            raise KeycloakException("Headers should be present.")

        location_with_user_uuid: str = response.headers.get("Location", "")

        user_uuid = location_with_user_uuid[location_with_user_uuid.rindex("/") + 1 :]

        if not user_uuid:
            raise ValueError("Invalid user uuid")

        return user_uuid

    async def update_user_async(
        self, user_id: UUID | str, payload: UpdateUserPayload
    ) -> None:
        response = await self._provider.update_user_by_id_async(
            user_id=user_id, payload=payload
        )

        self.validate_response(response)

    async def enable_user_async(
        self, user_id: UUID | str, payload: UserUpdateEnablePayload
    ) -> None:
        response = await self._provider.update_user_enable_by_id_async(
            user_id=user_id, payload=payload
        )

        self.validate_response(response)

    async def update_user_password_async(
        self, user_id: UUID | str, payload: UserUpdatePasswordPayload
    ) -> None:
        response = await self._provider.update_user_password_by_id_async(
            user_id=user_id, payload=payload
        )

        self.validate_response(response)

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

    async def assign_role_async(
        self, user_id: UUID | str, roles: list[RoleAssignPayload]
    ) -> JsonData:
        response = await self._provider.assign_role_async(user_id=user_id, roles=roles)

        return self.validate_response(response)

    async def unassign_role_async(
        self, user_id: UUID | str, roles: list[RoleAssignPayload]
    ) -> JsonData:
        response = await self._provider.unassign_role_async(
            user_id=user_id,
            roles=roles,
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
        response = await self._provider.get_user_info_async(access_token=access_token)

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
        await self._provider.logout_async(refresh_token=refresh_token)

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
    ) -> JsonData:
        response = await self._provider.auth_device_async()

        return self.validate_response(response)

    async def auth_device_async(
        self,
    ) -> DeviceAuthRepresentation:
        data = await self.auth_device_raw_async()

        return dataclass_from_dict(data, DeviceAuthRepresentation)

    ###
    # Certs
    ###

    async def get_certs_async(
        self,
    ) -> JsonData:
        response = await self._provider.get_certs_async()

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

        self.validate_response(response)

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
