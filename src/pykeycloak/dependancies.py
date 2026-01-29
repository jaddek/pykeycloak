from functools import lru_cache

from httpx import AsyncClient, AsyncHTTPTransport

from . import SensitiveDataSanitizer
from .core.clients import KeycloakHttpClientWrapperAsync
from .core.headers import HeadersFactory, HeadersProtocol
from .core.settings import ClientSettings, HttpTransportSettings
from .core.validator import KeycloakResponseValidator
from .factories import KeycloakServiceFactory
from .providers.providers import KeycloakProviderProtocol


def get_factory(provider: KeycloakProviderProtocol) -> KeycloakServiceFactory:
    return KeycloakServiceFactory(
        provider=provider,
        validator=KeycloakResponseValidator(),
    )


@lru_cache(maxsize=1)
def get_sanitizer() -> SensitiveDataSanitizer:
    return SensitiveDataSanitizer.from_env()


def get_headers_factory() -> HeadersProtocol:
    return HeadersFactory()


def get_async_client(
    client_settings: ClientSettings | None = None,
    transport_settings: HttpTransportSettings | None = None,
) -> AsyncClient:
    transport_settings = transport_settings or HttpTransportSettings()
    transport = AsyncHTTPTransport(**transport_settings.to_dict())

    client_settings = client_settings or ClientSettings()
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
