import asyncio
import logging
import os

from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.payloads import (
    UserCredentialsLoginPayload,
)
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.services.services import AuthService

logging.getLogger("pykeycloak").setLevel(logging.DEBUG)

kc_realm = os.getenv("KEYCLOAK_REALM_NAME", "some name")

username = "admin"
password = "password"  # noqa: S105


async def main():
    realm_client = RealmClient.from_env()
    # depends on provider it is possible to set up the approach of storing access tokens (in memory or shared)
    provider = KeycloakInMemoryProviderAsync(
        realm=kc_realm,
        realm_client=realm_client,
    )

    auth_service = AuthService(provider)

    ## this step is required as the service account client get the access token and refresh tokens for further operations

    await auth_service.client_login_async()
    # or client_login_raw_async()

    ## device login flow
    result = await auth_service.auth_device_raw_async()  # noqa: F841

    ## User login
    user_refresh_token = (
        await auth_service.user_login_async(  # or user_login_raw_async #noqa: F841
            payload=UserCredentialsLoginPayload(
                username=username,
                password=password,
            )
        )
    )

    ## getting user info
    result = await auth_service.get_user_info_async(  # noqa: F841
        access_token=user_refresh_token.access_token
    )

    ## logout
    result = await auth_service.logout_async(user_refresh_token.refresh_token)  # noqa: F841

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
