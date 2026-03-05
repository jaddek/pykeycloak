import asyncio

from typing import cast
from pykeycloak.core.clients import KeycloakHttpClientWrapperAsync
from pykeycloak.core.headers import HeadersFactory
from pykeycloak.core.helpers import getenv_required
from pykeycloak.core.protocols import KeycloakProviderProtocol, KeycloakServiceFactoryProtocol, KeycloakServiceFactoryProtocol
from pykeycloak.core.realm import Realm, RealmClient
from pykeycloak.dependancies import get_async_client, get_factory, ProviderConstructor, get_async_client_with_env
from pykeycloak.factories import KeycloakServiceFactory, KeycloakWellKnownFactory
from pykeycloak.providers.providers import KeycloakProviderAsync, KeycloakInMemoryProviderAsync

username = "admin"
password = "password"  # noqa: S105


async def main():
    factory: KeycloakWellKnownFactory = get_factory(
        realm=Realm(name="otago"),
        realm_client=RealmClient(
            client_id=getenv_required("KEYCLOAK_REALM_OTAGO_SERVICE_CLIENT_UUID"),
            client_uuid=getenv_required("KEYCLOAK_REALM_OTAGO_SERVICE_CLIENT_ID"),
            client_secret=getenv_required("KEYCLOAK_REALM_OTAGO_SERVICE_CLIENT_SECRET"),
        ),
        headers=HeadersFactory(),
        http_client_wrapper=KeycloakHttpClientWrapperAsync(client=get_async_client_with_env()),
        provider_cls=KeycloakInMemoryProviderAsync,
        factory_cls=KeycloakWellKnownFactory,
    )



    print(await factory.well_known.get_certs_async())


if __name__ == "__main__":
    asyncio.run(main())
