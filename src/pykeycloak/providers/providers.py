# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from typing import TYPE_CHECKING

from pykeycloak.core.clients import KeycloakHttpClientAsync
from pykeycloak.core.headers import HeadersProtocol
from pykeycloak.core.protocols import KeycloakProviderProtocol
from pykeycloak.core.realm import RealmClient
from pykeycloak.core.token_manager import TokenManager

from ._auth import AuthProvider
from ._authz import (
    AuthzPermissionProvider,
    AuthzPolicyProvider,
    AuthzResourceProvider,
    AuthzScopeProvider,
    AuthzSettingsProvider,
)
from ._base import KeycloakProviderBase
from ._clients import ClientsProvider
from ._roles import RolesProvider
from ._sessions import SessionsProvider
from ._users import UsersProvider


class KeycloakProviderAsync:
    def __init__(
        self,
        *,
        realm_client: RealmClient,
        headers: HeadersProtocol,
        wrapper: KeycloakHttpClientAsync,
    ) -> None:
        base = KeycloakProviderBase(
            realm_client=realm_client,
            kc_headers=headers,
            kc_client=wrapper,
        )
        token_manager = TokenManager()

        self._auth_provider = AuthProvider(base=base, token_manager=token_manager)
        get_token = self._auth_provider.get_client_access_token

        self._users_provider = UsersProvider(base=base, get_access_token=get_token)
        self._sessions_provider = SessionsProvider(
            base=base, get_access_token=get_token
        )
        self._roles_provider = RolesProvider(base=base, get_access_token=get_token)
        self._clients_provider = ClientsProvider(base=base, get_access_token=get_token)
        self._authz_settings_provider = AuthzSettingsProvider(
            base=base, get_access_token=get_token
        )
        self._authz_scope_provider = AuthzScopeProvider(
            base=base, get_access_token=get_token
        )
        self._authz_resource_provider = AuthzResourceProvider(
            base=base, get_access_token=get_token
        )
        self._authz_policy_provider = AuthzPolicyProvider(
            base=base, get_access_token=get_token
        )
        self._authz_permission_provider = AuthzPermissionProvider(
            base=base, get_access_token=get_token
        )

        self._base = base

    @property
    def auth(self) -> AuthProvider:
        return self._auth_provider

    @property
    def users(self) -> UsersProvider:
        return self._users_provider

    @property
    def sessions(self) -> SessionsProvider:
        return self._sessions_provider

    @property
    def roles(self) -> RolesProvider:
        return self._roles_provider

    @property
    def clients(self) -> ClientsProvider:
        return self._clients_provider

    @property
    def authz(self) -> AuthzSettingsProvider:
        return self._authz_settings_provider

    @property
    def authz_scope(self) -> AuthzScopeProvider:
        return self._authz_scope_provider

    @property
    def authz_resource(self) -> AuthzResourceProvider:
        return self._authz_resource_provider

    @property
    def authz_policy(self) -> AuthzPolicyProvider:
        return self._authz_policy_provider

    @property
    def authz_permission(self) -> AuthzPermissionProvider:
        return self._authz_permission_provider

    async def close_connection(self) -> None:
        await self._base.close_connection()


class KeycloakInMemoryProviderAsync(KeycloakProviderAsync): ...


if TYPE_CHECKING:
    _ch_kpa: KeycloakProviderProtocol = type[KeycloakProviderAsync]
    _ch_kpa_im: KeycloakProviderProtocol = type[KeycloakInMemoryProviderAsync]
