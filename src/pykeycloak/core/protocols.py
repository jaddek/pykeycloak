from typing import Any, Protocol
from uuid import UUID

from httpx._types import HeaderTypes

from pykeycloak.core.types import JsonData
from pykeycloak.providers.payloads import (
    ClientCredentialsLoginPayload,
    CreateUserPayload,
    ObtainTokenPayload,
    PermissionPayload,
    PermissionScopesPayload,
    RefreshTokenPayload,
    ResourcePayload,
    RoleAssignPayload,
    RolePayload,
    RolePolicyPayload,
    RTPExchangeTokenPayload,
    RTPIntrospectionPayload,
    SSOLoginPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
    UpdateUserPayload,
    UserAuthorisationCodePayload,
    UserCredentialsLoginPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
)
from pykeycloak.providers.queries import (
    BriefRepresentationQuery,
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
    DeviceAuthRepresentation,
    IntrospectRepresentation,
    PermissionRepresentation,
    ResourceRepresentation,
    ScopeRepresentation,
    SessionRepresentation,
    SessionsCountRepresentation,
    SessionsStatsRepresentation,
    TokenRepresentation,
    UserInfoRepresentation,
    UserRepresentation,
)


class KeycloakResponseProtocol(Protocol):
    status_code: int
    headers: HeaderTypes | None = (None,)

    @property
    def text(self) -> str: ...

    @property
    def content(self) -> bytes: ...

    def json(self, **kwargs: Any) -> JsonData: ...


class KeycloakResponseValidatorProtocol(Protocol):
    def validate(self, /, response: KeycloakResponseProtocol) -> JsonData: ...


class KeycloakProviderProtocol(Protocol):
    def get_sso_redirect_url(self, payload: SSOLoginPayload) -> str: ...

    async def refresh_token_async(
        self,
        payload: RefreshTokenPayload | RTPExchangeTokenPayload,
    ) -> KeycloakResponseProtocol: ...

    async def obtain_token_async(
        self,
        payload: ObtainTokenPayload,
    ) -> KeycloakResponseProtocol: ...

    async def introspect_token_async(
        self,
        payload: RTPIntrospectionPayload | TokenIntrospectionPayload,
    ) -> KeycloakResponseProtocol: ...

    async def auth_device_async(self) -> KeycloakResponseProtocol: ...

    async def get_certs_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def logout_async(self, refresh_token: str) -> KeycloakResponseProtocol: ...

    async def revoke_async(self, refresh_token: str) -> KeycloakResponseProtocol: ...

    async def get_user_info_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_uma_permission_async(
        self,
        payload: UMAAuthorizationPayload,
    ) -> KeycloakResponseProtocol: ...

    async def get_users_count_async(
        self,
        *,
        access_token: str = ...,
        query: GetUsersQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_users_async(
        self,
        *,
        access_token: str = ...,
        query: GetUsersQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_user_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def delete_user_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def create_user_async(
        self,
        payload: CreateUserPayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def update_user_by_id_async(
        self,
        user_id: UUID | str,
        payload: UpdateUserPayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def update_user_enable_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdateEnablePayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def update_user_password_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdatePasswordPayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_users_by_role_async(
        self,
        role_name: str,
        *,
        access_token: str = ...,
        request_query: RoleMembersListQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_user_sessions_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def delete_session_by_id_async(
        self,
        session_id: UUID | str,
        is_offline: bool,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_user_sessions_async(
        self,
        *,
        access_token: str = ...,
        request_query: PaginationQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_sessions_count_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_offline_sessions_async(
        self,
        *,
        access_token: str = ...,
        query: PaginationQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_offline_sessions_count_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def remove_user_sessions_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def logout_all_users_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_session_stats_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_sessions_async(
        self, *, access_token: str = ..., query: PaginationQuery | None = None
    ) -> KeycloakResponseProtocol: ...

    async def get_client_user_offline_sessions_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_roles_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_role_by_name_async(
        self,
        role_name: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def create_role_async(
        self,
        payload: RolePayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def update_role_by_id_async(
        self,
        role_id: UUID | str,
        payload: RolePayload,
        *,
        access_token: str = ...,
        skip_unexpected_behaviour_exception: bool = False,
    ) -> KeycloakResponseProtocol: ...

    async def update_role_by_name_async(
        self,
        role_name: str,
        payload: RolePayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def delete_role_by_id_async(
        self,
        role_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def delete_role_by_name_async(
        self,
        role_name: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def assign_role_async(
        self,
        user_id: UUID | str,
        roles: list[RoleAssignPayload],
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def unassign_role_async(
        self,
        user_id: UUID | str,
        roles: list[RoleAssignPayload],
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_composite_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
        request_query: BriefRepresentationQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_available_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_user_roles_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_clients_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_authz_settings(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_authz_scopes_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def create_client_authz_permission_based_on_resource_async(
        self,
        payload: PermissionPayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def create_client_authz_permission_based_on_scope_async(
        self,
        payload: PermissionPayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_permissions_async(
        self,
        *,
        access_token: str = ...,
        query: FindPermissionQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_permission_based_on_scope_by_id_async(
        self,
        permission_id: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_permission_based_on_resource_by_id_async(
        self,
        permission_id: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def delete_permission_async(
        self,
        permission_id: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def update_permission_scopes_async(
        self,
        permission_id: str,  # resource OR scope based permission
        payload: PermissionScopesPayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_resources_async(
        self, *, access_token: str = ..., query: ResourcesListQuery | None = None
    ) -> KeycloakResponseProtocol: ...

    async def create_resource_async(
        self,
        payload: ResourcePayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_resource_by_id_async(
        self,
        resource_id: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def delete_resource_by_id_async(
        self,
        resource_id: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_resource_permissions_async(
        self,
        resource_id: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def create_policy_role_async(
        self,
        payload: RolePolicyPayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def delete_policy_async(
        self,
        policy_id: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def create_policy_async(
        self,
        payload: PermissionPayload,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_policy_by_name_async(
        self,
        *,
        access_token: str = ...,
        query: FilterFindPolicyParams | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_associated_roles_async(
        self,
        policy_id: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_policy_authorisation_scopes_async(
        self,
        policy_id: str,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def get_policies_async(
        self,
        *,
        access_token: str = ...,
    ) -> KeycloakResponseProtocol: ...

    async def close_connection(self) -> None: ...


class KeycloakServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...


class UsersServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def get_user_raw_async(self, user_id: UUID | str) -> JsonData: ...

    async def get_user_async(self, user_id: UUID | str) -> UserRepresentation: ...

    async def get_users_count_async(
        self, query: GetUsersQuery | None = None
    ) -> int: ...

    async def get_users_raw_async(
        self, query: GetUsersQuery | None = None
    ) -> tuple[list[JsonData], int]: ...

    async def get_users_async(
        self, query: GetUsersQuery | None = None
    ) -> tuple[list[UserRepresentation], int]: ...

    async def get_all_users_async(self) -> tuple[list[UserRepresentation], int]: ...

    async def get_paginated_users_async(
        self,
        users_count: int,
        concurrency_limit: int = ...,
        query: GetUsersQuery | None = None,
    ) -> list[KeycloakResponseProtocol]: ...

    async def get_users_by_role_async(
        self, role_name: str, query: RoleMembersListQuery | None = None
    ) -> JsonData: ...

    async def create_user_async(self, payload: CreateUserPayload) -> str: ...

    async def update_user_async(
        self, user_id: UUID | str, payload: UpdateUserPayload
    ) -> None: ...

    async def enable_user_async(
        self, user_id: UUID | str, payload: UserUpdateEnablePayload
    ) -> None: ...

    async def update_user_password_async(
        self, user_id: UUID | str, payload: UserUpdatePasswordPayload
    ) -> None: ...

    async def delete_user_async(self, user_id: UUID | str) -> JsonData: ...


class RolesServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def get_client_roles_raw_async(self) -> JsonData: ...

    async def get_client_roles_async(self) -> JsonData: ...

    async def get_role_by_name_raw_async(self, role_name: str) -> JsonData: ...

    async def get_role_by_name_async(self, role_name: str) -> JsonData: ...

    async def create_role_raw_async(self, payload: RolePayload) -> JsonData: ...

    async def create_role_async(self, payload: RolePayload) -> JsonData: ...

    async def update_role_by_id_async(
        self,
        role_id: UUID,
        payload: RolePayload,
        skip_unexpected_behaviour_exception: bool = False,
    ) -> None: ...

    async def delete_role_by_id_async(self, role_id: UUID) -> JsonData: ...

    async def delete_role_by_name_async(self, role_name: str) -> JsonData: ...

    async def update_role_by_name_raw_async(
        self, role_name: str, payload: RolePayload
    ) -> JsonData: ...

    async def update_role_by_name_async(
        self, role_name: str, payload: RolePayload
    ) -> JsonData: ...

    async def assign_role_async(
        self, user_id: UUID | str, roles: list[RoleAssignPayload]
    ) -> JsonData: ...

    async def unassign_role_async(
        self, user_id: UUID | str, roles: list[RoleAssignPayload]
    ) -> JsonData: ...

    async def get_client_roles_of_user_async(self, user_id: UUID | str) -> JsonData: ...

    async def get_composite_client_roles_of_user_async(
        self, user_id: UUID | str
    ) -> JsonData: ...

    async def get_available_client_roles_of_user_async(
        self, user_id: UUID | str
    ) -> JsonData: ...

    async def get_user_roles_async(self, user_id: UUID | str) -> JsonData: ...


class SessionsServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def get_client_sessions_raw_async(
        self, query: PaginationQuery | None = None
    ) -> JsonData: ...

    async def get_client_sessions_async(
        self, query: PaginationQuery | None = None
    ) -> list[SessionRepresentation]: ...

    async def get_user_sessions_raw_async(self, user_id: UUID | str) -> JsonData: ...

    async def get_user_sessions_async(
        self, user_id: UUID | str
    ) -> list[SessionRepresentation]: ...

    async def get_client_sessions_count_raw_async(self) -> JsonData: ...

    async def get_client_sessions_count_async(self) -> SessionsCountRepresentation: ...

    async def get_offline_sessions_raw_async(
        self, query: PaginationQuery | None = None
    ) -> JsonData: ...

    async def get_offline_sessions_async(
        self, query: PaginationQuery | None = None
    ) -> list[SessionRepresentation]: ...

    async def get_offline_sessions_count_raw_async(self) -> JsonData: ...

    async def get_offline_sessions_count_async(self) -> SessionsCountRepresentation: ...

    async def remove_user_sessions_raw_async(self, user_id: UUID | str) -> JsonData: ...

    async def logout_all_users_raw_async(self) -> JsonData: ...

    async def logout_all_users_async(self) -> None: ...

    async def get_client_session_stats_raw_async(self) -> JsonData: ...

    async def get_client_session_stats_async(
        self,
    ) -> list[SessionsStatsRepresentation]: ...

    async def get_client_user_offline_sessions_raw_async(
        self, user_id: UUID | str
    ) -> JsonData: ...

    async def get_client_user_offline_sessions_async(
        self, user_id: UUID | str
    ) -> SessionRepresentation: ...

    async def delete_session_by_id_async(
        self, session_id: UUID | str, is_offline: bool
    ) -> JsonData: ...


class AuthServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    def get_redirect_code_url(self, payload: SSOLoginPayload) -> str: ...

    async def client_login_raw_async(self) -> JsonData: ...

    async def client_login_async(self) -> TokenRepresentation: ...

    async def user_login_raw_async(
        self, payload: UserCredentialsLoginPayload
    ) -> JsonData: ...

    async def exchange_code_to_token(
        self, payload: UserAuthorisationCodePayload
    ) -> JsonData: ...

    async def user_login_async(
        self, payload: UserCredentialsLoginPayload
    ) -> TokenRepresentation: ...

    async def obtain_token_raw_async(
        self,
        *,
        payload: ClientCredentialsLoginPayload | UserCredentialsLoginPayload,
    ) -> JsonData: ...

    async def obtain_token_async(
        self,
        *,
        payload: ClientCredentialsLoginPayload | UserCredentialsLoginPayload,
    ) -> TokenRepresentation: ...

    async def refresh_token_raw_async(
        self, payload: RefreshTokenPayload
    ) -> JsonData: ...

    async def refresh_token_async(
        self, payload: RefreshTokenPayload
    ) -> TokenRepresentation: ...

    async def get_user_info_raw_async(self, access_token: str) -> JsonData: ...

    async def get_user_info_async(
        self, access_token: str
    ) -> UserInfoRepresentation: ...

    async def logout_raw_async(self, refresh_token: str) -> JsonData: ...

    async def logout_async(self, refresh_token: str) -> None: ...

    async def introspect_token_raw_async(
        self, payload: RTPIntrospectionPayload | TokenIntrospectionPayload
    ) -> JsonData: ...

    async def introspect_token_async(
        self, payload: RTPIntrospectionPayload | TokenIntrospectionPayload
    ) -> IntrospectRepresentation: ...

    async def auth_device_raw_async(self) -> JsonData: ...

    async def auth_device_async(self) -> DeviceAuthRepresentation: ...

    async def revoke_raw_async(self, refresh_token: str) -> JsonData: ...

    async def revoke_async(self, refresh_token: str) -> None: ...

    async def get_uma_permission_async(
        self, payload: UMAAuthorizationPayload
    ) -> JsonData: ...


class UmaServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def get_uma_permissions_async(
        self, payload: UMAAuthorizationPayload
    ) -> JsonData: ...

    async def get_permissions_by_uris_chunks_async(
        self,
        payload: UMAAuthorizationPayload,
        chunk_size: int | None = None,
    ) -> list: ...


class ClientsServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def get_client_raw_async(self) -> JsonData: ...

    async def get_client_async(self) -> ClientRepresentation: ...

    async def get_clients_raw_async(self) -> JsonData: ...

    async def get_clients_async(self) -> list[ClientRepresentation]: ...


class AuthzServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def get_client_authz_settings_raw_async(self) -> JsonData: ...

    async def get_client_authz_settings_async(
        self,
    ) -> AuthzSettingsRepresentation: ...


class AuthzResourceServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def get_resources_raw_async(
        self, query: ResourcesListQuery | None = None
    ) -> JsonData: ...

    async def get_resources_async(
        self, query: ResourcesListQuery | None = None
    ) -> JsonData: ...

    async def create_resource_async(self, payload: ResourcePayload) -> JsonData: ...

    async def get_resource_by_id_raw_async(self, resource_id: str) -> JsonData: ...

    async def get_resource_by_id_async(
        self, resource_id: str
    ) -> ResourceRepresentation: ...

    async def delete_resource_by_id_async(self, resource_id: str) -> JsonData: ...

    async def get_resource_permissions_async(self, resource_id: str) -> JsonData: ...


class AuthzScopeServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def get_client_authz_scopes_raw_async(self) -> JsonData: ...

    async def get_client_authz_scopes_async(self) -> list[ScopeRepresentation]: ...


class AuthzPermissionServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def create_client_authz_permission_based_on_resource_async(
        self, payload: PermissionPayload
    ) -> JsonData: ...

    async def create_client_authz_permission_based_on_scope_async(
        self, payload: PermissionPayload
    ) -> JsonData: ...

    async def get_permissions_raw_async(
        self, query: FindPermissionQuery | None = None
    ) -> JsonData: ...

    async def get_permissions_async(
        self, query: FindPermissionQuery | None = None
    ) -> list[PermissionRepresentation]: ...

    async def get_permission_based_on_scope_by_id_async(
        self, permission_id: str
    ) -> JsonData: ...

    async def get_permission_based_on_resource_by_id_async(
        self, permission_id: str
    ) -> JsonData: ...

    async def delete_permission_async(self, permission_id: str) -> JsonData: ...

    async def update_permission_scopes_async(
        self,
        permission_id: str,
        payload: PermissionScopesPayload,
    ) -> JsonData: ...


class AuthPolicyServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def create_policy_role_async(
        self, payload: RolePolicyPayload
    ) -> JsonData: ...

    async def delete_policy_async(self, policy_id: str) -> JsonData: ...

    async def create_policy_async(self, payload: PermissionPayload) -> JsonData: ...

    async def get_policy_by_name_raw_async(
        self, query: FilterFindPolicyParams | None = None
    ) -> JsonData: ...

    async def get_policy_by_name_async(
        self, query: FilterFindPolicyParams | None = None
    ) -> JsonData: ...

    async def get_associated_roles_async(self, policy_id: str) -> JsonData: ...

    async def get_policy_authorisation_scopes_async(
        self, policy_id: str
    ) -> JsonData: ...

    async def get_policies_raw_async(self) -> JsonData: ...

    async def get_policies_async(self) -> JsonData: ...


class WellKnownServiceProtocol(Protocol):
    def validate_response(self, response: KeycloakResponseProtocol) -> JsonData: ...

    async def get_certs_async(self) -> JsonData: ...


class KeycloakServiceFactoryProtocol(Protocol):
    @property
    def provider(self) -> KeycloakProviderProtocol: ...

    @property
    def users(self) -> UsersServiceProtocol: ...

    @property
    def auth(self) -> AuthServiceProtocol: ...

    @property
    def authz(self) -> AuthzServiceProtocol: ...

    @property
    def roles(self) -> RolesServiceProtocol: ...

    @property
    def sessions(self) -> SessionsServiceProtocol: ...

    @property
    def uma(self) -> UmaServiceProtocol: ...

    @property
    def clients(self) -> ClientsServiceProtocol: ...

    @property
    def authz_resource(self) -> AuthzResourceServiceProtocol: ...

    @property
    def authz_permission(self) -> AuthzPermissionServiceProtocol: ...

    @property
    def authz_scope(self) -> AuthzScopeServiceProtocol: ...

    @property
    def auth_policy(self) -> AuthPolicyServiceProtocol: ...

    @property
    def well_known(self) -> WellKnownServiceProtocol: ...
