from .core.clients import KeycloakHttpClientAsync
from .core.headers import HeadersProtocol
from .core.protocols import KeycloakServiceFactoryProtocol
from .core.realm import RealmClient
from .core.validator import KeycloakResponseValidator
from .dependencies import (
    FactoryRegistry,
    KeycloakServiceFactory,
    get_headers_factory,
    get_keycloak_http_client_from_env,
    get_response_validator,
)
from .providers.providers import KeycloakInMemoryProviderAsync


class PyKeycloak:
    def __init__(self, registry: FactoryRegistry | None = None):
        self._registry = registry or FactoryRegistry()

    def get(self, key: str) -> KeycloakServiceFactoryProtocol:
        return self._registry.get(key)

    def register(
        self,
        key: str,
        realm_client: RealmClient,
        headers: HeadersProtocol | None = None,
        keycloak_http_client: KeycloakHttpClientAsync | None = None,
        keycloak_response_validator: KeycloakResponseValidator | None = None,
    ) -> None:
        factory = KeycloakServiceFactory(
            provider=KeycloakInMemoryProviderAsync(
                realm_client=realm_client,
                kc_headers=headers or get_headers_factory(),
                kc_client=keycloak_http_client or get_keycloak_http_client_from_env(),
            ),
            validator=keycloak_response_validator or get_response_validator(),
        )

        self._registry.register(key, factory)
