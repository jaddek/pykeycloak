from functools import cached_property
from typing import TypedDict

from pykeycloak.core.protocols import KeycloakResponseValidatorProtocol
from pykeycloak.providers.providers import KeycloakProviderProtocol
from pykeycloak.services.services import (
    AuthPolicyService,
    AuthService,
    AuthzPermissionService,
    AuthzResourceService,
    AuthzScopeService,
    AuthzService,
    ClientsService,
    RolesService,
    SessionsService,
    UmaService,
    UsersService,
)


class ServiceArgs(TypedDict):
    provider: KeycloakProviderProtocol
    validator: KeycloakResponseValidatorProtocol


class KeycloakServiceFactory:
    def __init__(
        self,
        provider: KeycloakProviderProtocol,
        validator: KeycloakResponseValidatorProtocol,
    ):
        self._args: ServiceArgs = {"provider": provider, "validator": validator}

    @cached_property
    def users(self) -> UsersService:
        return UsersService(**self._args)

    @cached_property
    def auth(self) -> AuthService:
        return AuthService(**self._args)

    @cached_property
    def authz(self) -> AuthzService:
        return AuthzService(**self._args)

    @cached_property
    def roles(self) -> RolesService:
        return RolesService(**self._args)

    @cached_property
    def sessions(self) -> SessionsService:
        return SessionsService(**self._args)

    @cached_property
    def uma(self) -> UmaService:
        return UmaService(**self._args)

    @cached_property
    def clients(self) -> ClientsService:
        return ClientsService(**self._args)

    @cached_property
    def authz_resource(self) -> AuthzResourceService:
        return AuthzResourceService(**self._args)

    @cached_property
    def authz_permission(self) -> AuthzPermissionService:
        return AuthzPermissionService(**self._args)

    @cached_property
    def authz_scope(self) -> AuthzScopeService:
        return AuthzScopeService(**self._args)

    @cached_property
    def auth_policy(self) -> AuthPolicyService:
        return AuthPolicyService(**self._args)
