from typing import Any, Protocol
from uuid import UUID

from httpx._types import HeaderTypes

from pykeycloak.core.types import JsonData
from pykeycloak.providers.payloads import (
    AuthRedirectPayload,
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


class ResponseProtocol(Protocol):
    status_code: int
    headers: HeaderTypes | None = (None,)

    @property
    def text(self) -> str: ...

    @property
    def content(self) -> bytes: ...

    def json(self, **kwargs: Any) -> JsonData: ...


class KeycloakResponseValidatorProtocol(Protocol):
    def validate(self, /, response: ResponseProtocol) -> JsonData: ...


class KeycloakProviderProtocol(Protocol):
    def get_sso_redirect_url(self, payload: AuthRedirectPayload) -> str: ...

    async def refresh_token_async(
        self,
        payload: RefreshTokenPayload | RTPExchangeTokenPayload,
    ) -> ResponseProtocol: ...

    async def obtain_token_async(
        self,
        payload: ObtainTokenPayload,
    ) -> ResponseProtocol: ...

    async def introspect_token_async(
        self,
        payload: RTPIntrospectionPayload | TokenIntrospectionPayload,
    ) -> ResponseProtocol: ...

    async def auth_device_async(self) -> ResponseProtocol: ...

    async def get_certs_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def logout_async(self, refresh_token: str) -> ResponseProtocol: ...

    async def revoke_async(self, refresh_token: str) -> ResponseProtocol: ...

    async def get_user_info_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_uma_permission_async(
        self,
        payload: UMAAuthorizationPayload,
    ) -> ResponseProtocol: ...

    async def get_users_count_async(
        self,
        *,
        access_token: str = ...,
        query: GetUsersQuery | None = None,
    ) -> ResponseProtocol: ...

    async def get_users_async(
        self,
        *,
        access_token: str = ...,
        query: GetUsersQuery | None = None,
    ) -> ResponseProtocol: ...

    async def get_user_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def delete_user_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def create_user_async(
        self,
        payload: CreateUserPayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def update_user_by_id_async(
        self,
        user_id: UUID | str,
        payload: UpdateUserPayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def update_user_enable_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdateEnablePayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def update_user_password_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdatePasswordPayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_users_by_role_async(
        self,
        role_name: str,
        *,
        access_token: str = ...,
        request_query: RoleMembersListQuery | None = None,
    ) -> ResponseProtocol: ...

    async def get_user_sessions_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def delete_session_by_id_async(
        self,
        session_id: UUID | str,
        is_offline: bool,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_client_user_sessions_async(
        self,
        *,
        access_token: str = ...,
        request_query: PaginationQuery | None = None,
    ) -> ResponseProtocol: ...

    async def get_client_sessions_count_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_offline_sessions_async(
        self,
        *,
        access_token: str = ...,
        query: PaginationQuery | None = None,
    ) -> ResponseProtocol: ...

    async def get_offline_sessions_count_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def remove_user_sessions_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def logout_all_users_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_client_session_stats_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_client_sessions_async(
        self, *, access_token: str = ..., query: PaginationQuery | None = None
    ) -> ResponseProtocol: ...

    async def get_client_user_offline_sessions_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_client_roles_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_role_by_name_async(
        self,
        role_name: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def create_role_async(
        self,
        payload: RolePayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def update_role_by_id_async(
        self,
        role_id: UUID | str,
        payload: RolePayload,
        *,
        access_token: str = ...,
        skip_unexpected_behaviour_exception: bool = False,
    ) -> ResponseProtocol: ...

    async def update_role_by_name_async(
        self,
        role_name: str,
        payload: RolePayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def delete_role_by_id_async(
        self,
        role_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def delete_role_by_name_async(
        self,
        role_name: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def assign_role_async(
        self,
        user_id: UUID | str,
        roles: list[RoleAssignPayload],
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def unassign_role_async(
        self,
        user_id: UUID | str,
        roles: list[RoleAssignPayload],
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_composite_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
        request_query: BriefRepresentationQuery | None = None,
    ) -> ResponseProtocol: ...

    async def get_available_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_user_roles_async(
        self,
        user_id: UUID | str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_clients_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_client_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_client_authz_settings(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_client_authz_scopes_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def create_client_authz_permission_based_on_resource_async(
        self,
        payload: PermissionPayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def create_client_authz_permission_based_on_scope_async(
        self,
        payload: PermissionPayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_permissions_async(
        self,
        *,
        access_token: str = ...,
        query: FindPermissionQuery | None = None,
    ) -> ResponseProtocol: ...

    async def get_permission_based_on_scope_by_id_async(
        self,
        permission_id: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_permission_based_on_resource_by_id_async(
        self,
        permission_id: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def delete_permission_async(
        self,
        permission_id: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def update_permission_scopes_async(
        self,
        permission_id: str,  # resource OR scope based permission
        payload: PermissionScopesPayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_resources_async(
        self, *, access_token: str = ..., query: ResourcesListQuery | None = None
    ) -> ResponseProtocol: ...

    async def create_resource_async(
        self,
        payload: ResourcePayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_resource_by_id_async(
        self,
        resource_id: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def delete_resource_by_id_async(
        self,
        resource_id: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_resource_permissions_async(
        self,
        resource_id: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def create_policy_role_async(
        self,
        payload: RolePolicyPayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def delete_policy_async(
        self,
        policy_id: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def create_policy_async(
        self,
        payload: PermissionPayload,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_policy_by_name_async(
        self,
        *,
        access_token: str = ...,
        query: FilterFindPolicyParams | None = None,
    ) -> ResponseProtocol: ...

    async def get_associated_roles_async(
        self,
        policy_id: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_policy_authorisation_scopes_async(
        self,
        policy_id: str,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def get_policies_async(
        self,
        *,
        access_token: str = ...,
    ) -> ResponseProtocol: ...

    async def close(self) -> None: ...
