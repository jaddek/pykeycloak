import asyncio

from pykeycloak.core.clients import KeycloakHttpClientAsync
from pykeycloak.core.headers import HeadersFactory
from pykeycloak.core.helpers import getenv_required
from pykeycloak.core.realm import Realm, RealmClient
from pykeycloak.dependancies import get_async_client_with_env, get_service_factory
from pykeycloak.factories import KeycloakServiceFactory
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync

username = "admin"
password = "password"  # noqa: S105


async def main():
    kc_realm = Realm(name="otago")
    kc_realm_client = RealmClient(
        client_uuid=getenv_required("KEYCLOAK_REALM_OTAGO_SERVICE_CLIENT_UUID"),
        client_id=getenv_required("KEYCLOAK_REALM_OTAGO_SERVICE_CLIENT_ID"),
        client_secret=getenv_required("KEYCLOAK_REALM_OTAGO_SERVICE_CLIENT_SECRET"),
    )

    kc_http_client = KeycloakHttpClientAsync(client=get_async_client_with_env())
    kc_http_headers = HeadersFactory()

    factory: KeycloakServiceFactory = get_service_factory(
        kc_realm=kc_realm,
        kc_realm_client=kc_realm_client,
        kc_http_client=kc_http_client,
        headers=kc_http_headers,
        provider_cls=KeycloakInMemoryProviderAsync,
    )

    await factory.auth.client_login_async()

    print(await factory.well_known.get_certs_async())


if __name__ == "__main__":
    asyncio.run(main())
