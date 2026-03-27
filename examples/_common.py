import logging

from pykeycloak.core.protocols import KeycloakServiceFactoryProtocol
from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.payloads import UserCredentialsLoginPayload
from pykeycloak.pykeycloak import PyKeycloak

logging.basicConfig(
    level=logging.DEBUG, format="%(name)s - %(levelname)s - %(message)s"
)

username = "admin"
password = "password"  # noqa: S105
default_realm_client = "otago_service"
__pkc = PyKeycloak()


def get_keycloak(key: str) -> KeycloakServiceFactoryProtocol:
    __pkc.register(key, RealmClient.from_env(client_name=key))

    return __pkc.get(key)


def get_user_credentials() -> UserCredentialsLoginPayload:
    return UserCredentialsLoginPayload(
        username=username,
        password=password,
    )
