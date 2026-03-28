from functools import cached_property
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING, Protocol

from httpx import AsyncClient, AsyncHTTPTransport

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

from . import SensitiveDataSanitizer
from .core.clients import KeycloakHttpClientAsync
from .core.headers import HeadersFactory, HeadersProtocol
from .core.protocols import (
    KeycloakProviderProtocol,
    KeycloakResponseValidatorProtocol,
    KeycloakServiceFactoryProtocol,
)
from .core.realm import RealmClient
from .core.settings import ClientSettings, HttpTransportSettings
from .core.validator import KeycloakResponseValidator


class FactoryRegistry:
    def __init__(self) -> None:
        self._map: dict[str, KeycloakServiceFactoryProtocol] = {}

    def register(
        self,
        instance_key: str,
        factory: KeycloakServiceFactoryProtocol,
    ) -> None:
        self._map[instance_key] = factory

    def unregister(self, instance_key: str) -> None:
        if instance_key not in self._map:
            raise KeyError(f"Key not found: {instance_key} in registered factories")
        del self._map[instance_key]

    def get(self, instance_key: str) -> KeycloakServiceFactoryProtocol:
        instance = self._map.get(instance_key)
        if not instance:
            raise KeyError(f"Provider with key {instance_key} not found")

        return instance

    async def close_all(self) -> None:
        errors: list[tuple[str, Exception]] = []

        for key, factory in self._map.items():
            try:
                await factory.provider.close_connection()
            except Exception as e:
                errors.append((key, e))

        if errors:
            error_details = "; ".join(f"key='{k}': {e}" for k, e in errors)
            raise RuntimeError(f"Errors during close_all: {error_details}")


class KeycloakServiceFactory:
    def __init__(
        self,
        provider: KeycloakProviderProtocol,
        validator: KeycloakResponseValidatorProtocol,
    ):
        self._provider = provider
        self._validator = validator

    @property
    def provider(self) -> KeycloakProviderProtocol:
        return self._provider

    @cached_property
    def users(self) -> UsersService:
        return UsersService(provider=self._provider.users, validator=self._validator)

    @cached_property
    def auth(self) -> AuthService:
        return AuthService(provider=self._provider.auth, validator=self._validator)

    @cached_property
    def authz(self) -> AuthzService:
        return AuthzService(provider=self._provider.authz, validator=self._validator)

    @cached_property
    def roles(self) -> RolesService:
        return RolesService(provider=self._provider.roles, validator=self._validator)

    @cached_property
    def sessions(self) -> SessionsService:
        return SessionsService(
            provider=self._provider.sessions, validator=self._validator
        )

    @cached_property
    def uma(self) -> UmaService:
        return UmaService(provider=self._provider.auth, validator=self._validator)

    @cached_property
    def clients(self) -> ClientsService:
        return ClientsService(
            provider=self._provider.clients, validator=self._validator
        )

    @cached_property
    def authz_resource(self) -> AuthzResourceService:
        return AuthzResourceService(
            provider=self._provider.authz_resource, validator=self._validator
        )

    @cached_property
    def authz_permission(self) -> AuthzPermissionService:
        return AuthzPermissionService(
            provider=self._provider.authz_permission, validator=self._validator
        )

    @cached_property
    def authz_scope(self) -> AuthzScopeService:
        return AuthzScopeService(
            provider=self._provider.authz_scope, validator=self._validator
        )

    @cached_property
    def authz_policy(self) -> AuthzPolicyService:
        return AuthzPolicyService(
            provider=self._provider.authz_policy, validator=self._validator
        )

    @cached_property
    def well_known(self) -> WellKnownService:
        return WellKnownService(provider=self._provider.auth, validator=self._validator)


class ProviderConstructor[T: KeycloakProviderProtocol](Protocol):
    def __call__(
        self,
        *,
        realm_client: RealmClient,
        headers: HeadersProtocol,
        wrapper: KeycloakHttpClientAsync,
    ) -> T: ...


def get_service_factory[T: KeycloakProviderProtocol](
    *,
    kc_realm_client: RealmClient,
    kc_http_client: KeycloakHttpClientAsync,
    headers: HeadersProtocol,
    provider_cls: ProviderConstructor[T],
) -> KeycloakServiceFactory:
    provider = provider_cls(
        realm_client=kc_realm_client,
        wrapper=kc_http_client,
        headers=headers,
    )

    return KeycloakServiceFactory(
        provider=provider,
        validator=KeycloakResponseValidator(),
    )


def get_sanitizer() -> SensitiveDataSanitizer:
    return SensitiveDataSanitizer.from_env()


def get_headers_factory() -> HeadersProtocol:
    return HeadersFactory()


def get_response_validator() -> KeycloakResponseValidatorProtocol:
    return KeycloakResponseValidator()


def get_package_name() -> str:
    return "pykeycloak"


def get_default_user_agent() -> dict[str, str]:
    package = get_package_name()

    try:
        __version__ = version(package)
    except PackageNotFoundError:
        __version__ = "0.1.0-dev"

    return {
        "User-Agent": f"{package}/{__version__}",
    }


def get_async_client(
    client_settings: ClientSettings | None = None,
    transport_settings: HttpTransportSettings | None = None,
) -> AsyncClient:
    transport_settings = transport_settings or HttpTransportSettings()
    transport = AsyncHTTPTransport(**transport_settings.to_dict())

    if not client_settings:
        client_settings = ClientSettings(headers=get_default_user_agent())

    if not client_settings.headers:
        client_settings.headers = get_default_user_agent()

    if not client_settings.headers.get("User-Agent"):
        client_settings.headers |= get_default_user_agent()

    client_settings.transport = transport

    return AsyncClient(**client_settings.to_dict())


def get_async_client_with_env() -> AsyncClient:
    return get_async_client(
        client_settings=ClientSettings.with_env(),
        transport_settings=HttpTransportSettings.with_env(),
    )


def get_keycloak_http_client(
    *,
    client: AsyncClient,
) -> KeycloakHttpClientAsync:
    return KeycloakHttpClientAsync(
        client=client,
    )


def get_keycloak_http_client_from_env() -> KeycloakHttpClientAsync:
    return KeycloakHttpClientAsync(
        client=get_async_client_with_env(),
    )


if TYPE_CHECKING:
    _ksfp: KeycloakServiceFactoryProtocol = type[KeycloakServiceFactory]
