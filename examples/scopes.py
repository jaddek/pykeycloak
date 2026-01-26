import asyncio
import logging
import os

from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.services.services import AuthService, AuthzScopeService

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
    authz_service = AuthzScopeService(provider)

    await auth_service.client_login_async()

    raw_scopes = await authz_service.get_client_authz_scopes_raw_async()
    scopes = await authz_service.get_client_authz_scopes_async()

    print(f"Scopes raw: {raw_scopes}")
    print(f"Scopes objects: {scopes}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
