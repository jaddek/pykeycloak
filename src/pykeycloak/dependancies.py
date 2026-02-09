from importlib.metadata import PackageNotFoundError, version
from typing import Protocol

from httpx import AsyncClient, AsyncHTTPTransport

from . import SensitiveDataSanitizer
from .core.clients import KeycloakHttpClientWrapperAsync
from .core.headers import HeadersFactory, HeadersProtocol
from .core.protocols import KeycloakProviderProtocol
from .core.realm import Realm, RealmClient
from .core.settings import ClientSettings, HttpTransportSettings
from .core.validator import KeycloakResponseValidator
from .factories import KeycloakServiceFactory


class ProviderConstructor[T: KeycloakProviderProtocol](Protocol):
    def __call__(
        self,
        *,
        realm: Realm,
        realm_client: RealmClient,
        headers: HeadersProtocol,
        wrapper: KeycloakHttpClientWrapperAsync,
    ) -> T: ...


def get_factory[T: KeycloakProviderProtocol](
    realm_name: str, client_name: str, provider_cls: ProviderConstructor[T]
) -> tuple[Realm, T, KeycloakServiceFactory]:
    realm = Realm(name=realm_name)

    provider = provider_cls(
        realm=realm,
        realm_client=RealmClient.from_env(client_name=client_name),
        headers=get_headers_factory(),
        wrapper=get_keycloak_client_wrapper_from_env(),
    )

    factory = KeycloakServiceFactory(
        provider=provider,
        validator=KeycloakResponseValidator(),
    )

    return realm, provider, factory


def get_sanitizer() -> SensitiveDataSanitizer:
    return SensitiveDataSanitizer.from_env()


def get_headers_factory() -> HeadersProtocol:
    return HeadersFactory()


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


def get_async_client_from_env() -> AsyncClient:
    return get_async_client(
        client_settings=ClientSettings.from_env(),
        transport_settings=HttpTransportSettings.from_env(),
    )


def get_keycloak_client_wrapper(
    *,
    client: AsyncClient,
) -> KeycloakHttpClientWrapperAsync:
    return KeycloakHttpClientWrapperAsync(
        client=client,
    )


def get_keycloak_client_wrapper_from_env() -> KeycloakHttpClientWrapperAsync:
    return KeycloakHttpClientWrapperAsync(
        client=get_async_client_from_env(),
    )
