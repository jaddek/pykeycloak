import logging
import os

from pykeycloak.core.realm import Realm, RealmClient
from pykeycloak.providers.providers import (
    KeycloakInMemoryProviderAsync,
    KeycloakProviderProtocol,
)
from pykeycloak.services.services import AuthService

logging.getLogger("pykeycloak").setLevel(logging.DEBUG)

kc_realm = os.getenv("KEYCLOAK_REALM_NAME", "some name")

username = "admin"
password = "password"  # noqa: S105


async def auth() -> tuple[KeycloakProviderProtocol, AuthService]:
    realm_client = RealmClient.from_env()
    realm = Realm(realm_name=kc_realm)
    # depends on provider it is possible to set up the approach of storing access tokens (in memory or shared)
    provider = KeycloakInMemoryProviderAsync(
        realm=realm,
        realm_client=realm_client,
    )

    auth_service = AuthService(provider)

    ## this step is required as the service account client get the access token and refresh tokens for further operations

    await auth_service.client_login_async()  # or client_login_raw_async()

    return provider, auth_service
