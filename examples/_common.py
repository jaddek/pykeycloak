import logging
import os

from pykeycloak.core.clients import get_keycloak_client_wrapper_from_env
from pykeycloak.core.headers import get_headers_factory
from pykeycloak.core.realm import Realm, RealmClient
from pykeycloak.core.validator import KeycloakResponseValidator
from pykeycloak.providers.providers import (
    KeycloakInMemoryProviderAsync,
)
from pykeycloak.services.factory import KeycloakServiceFactory

# logging.basicConfig(
#     level=logging.DEBUG, format="%(name)s - %(levelname)s - %(message)s"
# )
logging.getLogger("pykeycloak").setLevel(logging.DEBUG)

kc_realm = os.getenv("KEYCLOAK_REALM_NAME", "some name")

username = "admin"
password = "password"  # noqa: S105


async def service_factory() -> KeycloakServiceFactory:
    realm_client = RealmClient.from_env()
    realm = Realm(realm_name=kc_realm)
    factory = KeycloakServiceFactory(
        provider=KeycloakInMemoryProviderAsync(
            realm=realm,
            realm_client=realm_client,
            headers=get_headers_factory(),
            wrapper=get_keycloak_client_wrapper_from_env(),
        ),
        validator=KeycloakResponseValidator(),
    )

    ## this step is required as the service account client get the access token and refresh tokens for further operations
    await factory.auth.client_login_async()  # or client_login_raw_async()

    return factory
