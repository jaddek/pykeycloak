from abc import ABC, abstractmethod
from functools import cached_property
from typing import TypedDict, cast

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
    WellKnownService,
)

from .core.protocols import (
    KeycloakProviderProtocol,
    KeycloakResponseValidatorProtocol,
    KeycloakServiceProtocol,
)


class ServiceArgs(TypedDict):
    provider: KeycloakProviderProtocol
    validator: KeycloakResponseValidatorProtocol


class KeycloakBaseServiceFactory(ABC):
    def __init__(
        self,
        provider: KeycloakProviderProtocol,
        validator: KeycloakResponseValidatorProtocol,
    ):
        self._provider = provider
        self._args: ServiceArgs = {"provider": provider, "validator": validator}

    @property
    def provider(self) -> KeycloakProviderProtocol:
        return self._provider

    def service(self, name: str | None = None) -> KeycloakServiceProtocol:
        if not name:
            return self.default_service()

        if not hasattr(self, name):
            raise ValueError(f"Service method name '{name}' is not defined")

        return cast(KeycloakServiceProtocol, getattr(self, name))

    @abstractmethod
    def default_service(self) -> KeycloakServiceProtocol: ...


class KeycloakWellKnownFactory(KeycloakBaseServiceFactory):
    __default_service_name = "well_known"



    @cached_property
    def well_known(self) -> WellKnownService:
        return WellKnownService(**self._args)

    def default_service(self) -> KeycloakServiceProtocol:
        return self.service(name=self.__default_service_name)


class KeycloakServiceFactory(KeycloakBaseServiceFactory):
    __default_service_name = "auth"

    def default_service(self) -> KeycloakServiceProtocol:
        return self.service(name=self.__default_service_name)

    @property
    def provider(self) -> KeycloakProviderProtocol:
        return self._provider

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
