import asyncio
import logging
import os

from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.services.services import AuthService, AuthzService

logging.basicConfig(level=logging.DEBUG)
kc_realm = os.getenv("KEYCLOAK_REALM_NAME", "otago")

username = "admin"
password = "password"  # noqa: S105


async def main():
    realm_client = RealmClient.from_env()
    provider = KeycloakInMemoryProviderAsync(
        realm=kc_realm,
        realm_client=realm_client,
    )

    auth_service = AuthService(provider)
    authz_service = AuthzService(provider)

    await auth_service.client_login_async()

    # Get client authorization settings with typed representation
    authz_settings = await authz_service.get_client_authz_settings_async()

    authz_settings_raw = await authz_service.get_client_authz_settings_raw_async()

    print(f"Authz settings: {authz_settings}")
    print(f"Authz raw settings: {authz_settings_raw}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
