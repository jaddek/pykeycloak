import asyncio
import logging
import os

from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.payloads import TokenIntrospectionPayload, RefreshTokenPayload, UserCredentialsLoginPayload
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.services.services import AuthService

logging.basicConfig(level=logging.DEBUG)
kc_realm = os.getenv("KEYCLOAK_REALM_NAME")

username = "admin"
password = "password"

async def main():
    realm_client = RealmClient.from_env()
    # depends on provider it is possible to set up the approach of storing access tokens (in memory or shared)
    provider = KeycloakInMemoryProviderAsync(
        realm=kc_realm,
        realm_client=realm_client,
    )

    auth_service = AuthService(provider)

    ## this step is required as the service account client get the access token and refresh tokens for further operations
    service_account_login = await auth_service.client_login_async() # or client_login_raw_async()

    ## device login flow
    result = await auth_service.auth_device_raw_async()

    ## certs
    result = await auth_service.get_certs_raw_async()

    ## refresh token
    refresh = await auth_service.refresh_token_async(
        payload=RefreshTokenPayload(refresh_token=service_account_login.refresh_token)
    )

    ## introspec async (RTP or Token depends on payload)
    result = await auth_service.introspect_async(
        payload=TokenIntrospectionPayload(
            token=refresh.auth_token,
        )
    )

    ## User login
    result = await auth_service.user_login_async( # or user_login_raw_async
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    ## getting user info
    result = await auth_service.get_user_info_async(
        access_token=refresh.auth_token
    )

    ## logout
    result = await auth_service.logout_async(refresh.refresh_token)

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
