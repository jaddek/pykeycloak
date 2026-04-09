from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from httpx._types import HeaderTypes

from pykeycloak.core.types import JsonData
from pykeycloak.providers.payloads import (
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

if TYPE_CHECKING:
    from pykeycloak.services.services import (
        AuthService,
        AuthzPermissionService,
        AuthzPolicyService,
        AuthzResourceService,
        AuthzScopeService,
        AuthzService,
        ClientsService,
        RolesService,
        SessionsService,
        UmaService,
        UsersService,
        WellKnownService,
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
    def validate(self, /, response: KeycloakResponseProtocol) -> None: ...


class AuthProviderProtocol(Protocol):
    def get_sso_redirect_url(self, payload: SSOLoginPayload) -> str: ...

    async def obtain_token_async(
        self,
        payload: ObtainTokenPayload,
    ) -> KeycloakResponseProtocol: ...

    async def refresh_token_async(
        self,
        payload: RefreshTokenPayload | RTPExchangeTokenPayload,
    ) -> KeycloakResponseProtocol: ...

    async def introspect_token_async(
        self,
        payload: RTPIntrospectionPayload | TokenIntrospectionPayload,
    ) -> KeycloakResponseProtocol: ...

    async def auth_device_async(self) -> KeycloakResponseProtocol: ...

    async def get_issuer_async(self) -> KeycloakResponseProtocol: ...

    async def get_openid_configuration_async(self) -> KeycloakResponseProtocol: ...

    async def get_uma2_configuration_async(self) -> KeycloakResponseProtocol: ...

    async def get_certs_async(self) -> KeycloakResponseProtocol: ...

    async def logout_async(self, refresh_token: str) -> KeycloakResponseProtocol: ...

    async def revoke_async(self, refresh_token: str) -> KeycloakResponseProtocol: ...

    async def get_user_info_async(
        self,
        *,
        access_token: str,
    ) -> KeycloakResponseProtocol: ...

    async def get_uma_permission_async(
        self,
        payload: UMAAuthorizationPayload,
    ) -> KeycloakResponseProtocol: ...


class UsersProviderProtocol(Protocol):
    async def get_users_count_async(
        self,
        query: GetUsersQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_users_async(
        self,
        query: GetUsersQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_user_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol: ...

    async def delete_user_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol: ...

    async def create_user_async(
        self,
        payload: CreateUserPayload,
    ) -> KeycloakResponseProtocol: ...

    async def update_user_by_id_async(
        self,
        user_id: UUID | str,
        payload: UpdateUserPayload,
    ) -> KeycloakResponseProtocol: ...

    async def update_user_enable_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdateEnablePayload,
    ) -> KeycloakResponseProtocol: ...

    async def update_user_password_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdatePasswordPayload,
    ) -> KeycloakResponseProtocol: ...

    async def get_users_by_role_async(
        self,
        role_name: str,
        request_query: RoleMembersListQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def impersonate_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol: ...


class SessionsProviderProtocol(Protocol):
    async def get_user_sessions_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol: ...

    async def delete_session_by_id_async(
        self,
        session_id: UUID | str,
        is_offline: bool,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_user_sessions_async(
        self,
        request_query: PaginationQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_sessions_count_async(self) -> KeycloakResponseProtocol: ...

    async def get_offline_sessions_async(
        self,
        query: PaginationQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_offline_sessions_count_async(self) -> KeycloakResponseProtocol: ...

    async def remove_user_sessions_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol: ...

    async def logout_all_users_async(self) -> KeycloakResponseProtocol: ...

    async def get_client_session_stats_async(self) -> KeycloakResponseProtocol: ...

    async def get_client_sessions_async(
        self,
        query: PaginationQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_client_user_offline_sessions_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol: ...


class RolesProviderProtocol(Protocol):
    async def get_client_roles_async(self) -> KeycloakResponseProtocol: ...

    async def get_role_by_name_async(
        self,
        role_name: str,
    ) -> KeycloakResponseProtocol: ...

    async def create_role_async(
        self,
        payload: RolePayload,
    ) -> KeycloakResponseProtocol: ...

    async def update_role_by_id_async(
        self,
        role_id: UUID | str,
        payload: RolePayload,
        skip_unexpected_behaviour_exception: bool = False,
    ) -> KeycloakResponseProtocol: ...

    async def update_role_by_name_async(
        self,
        role_name: str,
        payload: RolePayload,
    ) -> KeycloakResponseProtocol: ...

    async def delete_role_by_id_async(
        self,
        role_id: UUID | str,
    ) -> KeycloakResponseProtocol: ...

    async def delete_role_by_name_async(
        self,
        role_name: str,
    ) -> KeycloakResponseProtocol: ...

    async def assign_role_async(
        self,
        user_id: UUID | str,
        roles: list[RoleAssignPayload],
    ) -> KeycloakResponseProtocol: ...

    async def unassign_role_async(
        self,
        user_id: UUID | str,
        roles: list[RoleAssignPayload],
    ) -> KeycloakResponseProtocol: ...

    async def get_client_roles_of_user_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol: ...

    async def get_composite_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        request_query: BriefRepresentationQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_available_client_roles_of_user_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol: ...

    async def get_user_roles_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol: ...


class ClientsProviderProtocol(Protocol):
    async def get_clients_async(self) -> KeycloakResponseProtocol: ...

    async def get_client_async(self) -> KeycloakResponseProtocol: ...


class UmaProviderProtocol(Protocol):
    async def get_uma_permission_async(
        self,
        payload: UMAAuthorizationPayload,
    ) -> KeycloakResponseProtocol: ...


class AuthzProviderProtocol(Protocol):
    async def get_client_authz_settings(self) -> KeycloakResponseProtocol: ...


class AuthzScopeProviderProtocol(Protocol):
    async def get_client_authz_scopes_async(self) -> KeycloakResponseProtocol: ...


class AuthzResourceProviderProtocol(Protocol):
    async def get_resources_async(
        self,
        query: ResourcesListQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def create_resource_async(
        self,
        payload: ResourcePayload,
    ) -> KeycloakResponseProtocol: ...

    async def get_resource_by_id_async(
        self,
        resource_id: str,
    ) -> KeycloakResponseProtocol: ...

    async def delete_resource_by_id_async(
        self,
        resource_id: str,
    ) -> KeycloakResponseProtocol: ...

    async def get_resource_permissions_async(
        self,
        resource_id: str,
    ) -> KeycloakResponseProtocol: ...


class AuthzPermissionProviderProtocol(Protocol):
    async def create_client_authz_permission_based_on_resource_async(
        self,
        payload: PermissionPayload,
    ) -> KeycloakResponseProtocol: ...

    async def create_client_authz_permission_based_on_scope_async(
        self,
        payload: PermissionPayload,
    ) -> KeycloakResponseProtocol: ...

    async def get_permissions_async(
        self,
        query: FindPermissionQuery | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_permission_based_on_scope_by_id_async(
        self,
        permission_id: str,
    ) -> KeycloakResponseProtocol: ...

    async def get_permission_based_on_resource_by_id_async(
        self,
        permission_id: str,
    ) -> KeycloakResponseProtocol: ...

    async def delete_permission_async(
        self,
        permission_id: str,
    ) -> KeycloakResponseProtocol: ...

    async def update_permission_scopes_async(
        self,
        permission_id: str,
        payload: PermissionScopesPayload,
    ) -> KeycloakResponseProtocol: ...


class AuthzPolicyProviderProtocol(Protocol):
    async def create_policy_role_async(
        self,
        payload: RolePolicyPayload,
    ) -> KeycloakResponseProtocol: ...

    async def delete_policy_async(
        self,
        policy_id: str,
    ) -> KeycloakResponseProtocol: ...

    async def create_policy_async(
        self,
        payload: PermissionPayload,
    ) -> KeycloakResponseProtocol: ...

    async def get_policy_by_name_async(
        self,
        query: FilterFindPolicyParams | None = None,
    ) -> KeycloakResponseProtocol: ...

    async def get_associated_roles_async(
        self,
        policy_id: str,
    ) -> KeycloakResponseProtocol: ...

    async def get_policy_authorisation_scopes_async(
        self,
        policy_id: str,
    ) -> KeycloakResponseProtocol: ...

    async def get_policies_async(self) -> KeycloakResponseProtocol: ...


class KeycloakProviderProtocol(Protocol):
    @property
    def auth(self) -> AuthProviderProtocol: ...

    @property
    def users(self) -> UsersProviderProtocol: ...

    @property
    def sessions(self) -> SessionsProviderProtocol: ...

    @property
    def roles(self) -> RolesProviderProtocol: ...

    @property
    def clients(self) -> ClientsProviderProtocol: ...

    @property
    def authz(self) -> AuthzProviderProtocol: ...

    @property
    def authz_scope(self) -> AuthzScopeProviderProtocol: ...

    @property
    def authz_resource(self) -> AuthzResourceProviderProtocol: ...

    @property
    def authz_policy(self) -> AuthzPolicyProviderProtocol: ...

    @property
    def authz_permission(self) -> AuthzPermissionProviderProtocol: ...

    async def close_connection(self) -> None: ...


class KeycloakServiceFactoryProtocol(Protocol):
    @property
    def provider(self) -> KeycloakProviderProtocol: ...

    @property
    def users(self) -> UsersService: ...

    @property
    def auth(self) -> AuthService: ...

    @property
    def authz(self) -> AuthzService: ...

    @property
    def roles(self) -> RolesService: ...

    @property
    def sessions(self) -> SessionsService: ...

    @property
    def uma(self) -> UmaService: ...

    @property
    def clients(self) -> ClientsService: ...

    @property
    def authz_resource(self) -> AuthzResourceService: ...

    @property
    def authz_permission(self) -> AuthzPermissionService: ...

    @property
    def authz_scope(self) -> AuthzScopeService: ...

    @property
    def authz_policy(self) -> AuthzPolicyService: ...

    @property
    def well_known(self) -> WellKnownService: ...
