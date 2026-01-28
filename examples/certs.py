import asyncio
import logging
import os

from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.services.services import AuthService

logging.getLogger("pykeycloak").setLevel(logging.DEBUG)

kc_realm = os.getenv("KEYCLOAK_REALM_NAME", "otago")


async def main():
    realm_client = RealmClient.from_env()
    provider = KeycloakInMemoryProviderAsync(
        realm=kc_realm,
        realm_client=realm_client,
    )

    auth_service = AuthService(provider)

    # Service account login required to get access to admin operations
    await auth_service.client_login_async()

    # Get certificates using the access token
    certs = await auth_service.get_certs_async()
    print(f"Certificates: {certs}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
