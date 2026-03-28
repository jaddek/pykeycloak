# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from collections.abc import Awaitable, Callable

from pykeycloak.core.clients import HttpMethod
from pykeycloak.core.protocols import KeycloakResponseProtocol
from pykeycloak.core.urls import (
    REALM_CLIENT_AUTHZ_CLIENT_POLICY_ASSOCIATED_ROLE_POLICIES,
    REALM_CLIENT_AUTHZ_PERMISSION_BASED_ON_RESOURCE,
    REALM_CLIENT_AUTHZ_PERMISSION_BASED_ON_SCOPES,
    REALM_CLIENT_AUTHZ_PERMISSIONS,
    REALM_CLIENT_AUTHZ_PERMISSIONS_BASED_ON_RESOURCE,
    REALM_CLIENT_AUTHZ_PERMISSIONS_BASED_ON_SCOPES,
    REALM_CLIENT_AUTHZ_POLICIES,
    REALM_CLIENT_AUTHZ_POLICY,
    REALM_CLIENT_AUTHZ_POLICY_ROLE,
    REALM_CLIENT_AUTHZ_POLICY_SCOPES,
    REALM_CLIENT_AUTHZ_POLICY_SEARCH,
    REALM_CLIENT_AUTHZ_POLICY_USER,
    REALM_CLIENT_AUTHZ_RESOURCE,
    REALM_CLIENT_AUTHZ_RESOURCE_PERMISSIONS,
    REALM_CLIENT_AUTHZ_RESOURCES,
    REALM_CLIENT_AUTHZ_SCOPES,
    REALM_CLIENT_AUTHZ_SETTINGS,
)

from ._base import KeycloakProviderBase
from .payloads import (
    PermissionPayload,
    PermissionScopesPayload,
    ResourcePayload,
    RolePolicyPayload,
)
from .queries import FilterFindPolicyParams, FindPermissionQuery, ResourcesListQuery


class AuthzSettingsProvider:
    def __init__(
        self,
        base: KeycloakProviderBase,
        get_access_token: Callable[[], Awaitable[str]],
    ) -> None:
        self._base = base
        self._get_access_token = get_access_token

    async def get_client_authz_settings(self) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_AUTHZ_SETTINGS),
            headers=self._base.bearer_headers(access_token),
        )


class AuthzScopeProvider:
    def __init__(
        self,
        base: KeycloakProviderBase,
        get_access_token: Callable[[], Awaitable[str]],
    ) -> None:
        self._base = base
        self._get_access_token = get_access_token

    async def get_client_authz_scopes_async(self) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_AUTHZ_SCOPES),
            headers=self._base.bearer_headers(access_token),
        )


class AuthzResourceProvider:
    def __init__(
        self,
        base: KeycloakProviderBase,
        get_access_token: Callable[[], Awaitable[str]],
    ) -> None:
        self._base = base
        self._get_access_token = get_access_token

    async def get_resources_async(
        self,
        query: ResourcesListQuery | None = None,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_AUTHZ_RESOURCES),
            headers=self._base.bearer_headers(access_token),
            params=query.to_dict() if query else None,
        )

    async def create_resource_async(
        self,
        payload: ResourcePayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_AUTHZ_RESOURCES),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_json(),
        )

    async def get_resource_by_id_async(
        self,
        resource_id: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_RESOURCE, resource_id=resource_id
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def delete_resource_by_id_async(
        self,
        resource_id: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.DELETE,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_RESOURCE, resource_id=resource_id
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_resource_permissions_async(
        self,
        resource_id: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_RESOURCE_PERMISSIONS, resource_id=resource_id
            ),
            headers=self._base.bearer_headers(access_token),
        )


class AuthzPolicyProvider:
    def __init__(
        self,
        base: KeycloakProviderBase,
        get_access_token: Callable[[], Awaitable[str]],
    ) -> None:
        self._base = base
        self._get_access_token = get_access_token

    async def create_policy_role_async(
        self,
        payload: RolePolicyPayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_AUTHZ_POLICY_ROLE),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_json(),
        )

    async def delete_policy_async(
        self,
        policy_id: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.DELETE,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_POLICY, policy_id=policy_id
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def create_policy_async(
        self,
        payload: PermissionPayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_AUTHZ_POLICY_USER),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_json(),
        )

    async def get_policy_by_name_async(
        self,
        query: FilterFindPolicyParams | None = None,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_AUTHZ_POLICY_SEARCH),
            headers=self._base.bearer_headers(access_token),
            params=query.to_dict() if query else None,
        )

    async def get_associated_roles_async(
        self,
        policy_id: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_CLIENT_POLICY_ASSOCIATED_ROLE_POLICIES,
                policy_id=policy_id,
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_policy_authorisation_scopes_async(
        self,
        policy_id: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_POLICY_SCOPES, policy_id=policy_id
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_policies_async(self) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_AUTHZ_POLICIES),
            headers=self._base.bearer_headers(access_token),
        )


class AuthzPermissionProvider:
    def __init__(
        self,
        base: KeycloakProviderBase,
        get_access_token: Callable[[], Awaitable[str]],
    ) -> None:
        self._base = base
        self._get_access_token = get_access_token

    async def create_client_authz_permission_based_on_resource_async(
        self,
        payload: PermissionPayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_PERMISSIONS_BASED_ON_RESOURCE
            ),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_dict(),
        )

    async def create_client_authz_permission_based_on_scope_async(
        self,
        payload: PermissionPayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_PERMISSIONS_BASED_ON_SCOPES
            ),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_dict(),
        )

    async def get_permissions_async(
        self,
        query: FindPermissionQuery | None = None,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_AUTHZ_PERMISSIONS),
            headers=self._base.bearer_headers(access_token),
            params=query.to_dict() if query else None,
        )

    async def get_permission_based_on_scope_by_id_async(
        self,
        permission_id: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_PERMISSION_BASED_ON_SCOPES,
                permission_id=permission_id,
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_permission_based_on_resource_by_id_async(
        self,
        permission_id: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_PERMISSION_BASED_ON_RESOURCE,
                permission_id=permission_id,
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def delete_permission_async(
        self,
        permission_id: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.DELETE,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_PERMISSION_BASED_ON_RESOURCE,
                permission_id=permission_id,
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def update_permission_scopes_async(
        self,
        permission_id: str,
        payload: PermissionScopesPayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.PUT,
            url=self._base.build_url(
                path=REALM_CLIENT_AUTHZ_PERMISSION_BASED_ON_SCOPES,
                permission_id=permission_id,
            ),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_dict(),
        )
