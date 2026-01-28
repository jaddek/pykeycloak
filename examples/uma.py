import asyncio
import logging
import os

from pykeycloak.core.enums import UrnIetfOauthUmaTicketResponseModeEnum
from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.payloads import (
    UMAAuthorizationPayload,
    UserCredentialsLoginPayload,
)
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.services.services import AuthService, UmaService

logging.getLogger("pykeycloak").setLevel(logging.DEBUG)

kc_realm = os.getenv("KEYCLOAK_REALM_NAME", "Some name")

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
    uma_service = UmaService(provider)

    ## this step is required as the service account client get the access token and refresh tokens for further operations
    await auth_service.client_login_async()  # or client_login_raw_async()

    result = await auth_service.user_login_async(  # or user_login_raw_async
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    ## response with available permissions (could be 401 if no permissions)
    ## this request should be batched as KC has limitations on amount of permissions it could check at one request
    result = await uma_service.get_uma_permissions_async(
        payload=UMAAuthorizationPayload(
            audience=realm_client.client_id,
            permissions={"/otago/users": ["view"]},
            subject_token=result.access_token,
            response_mode=UrnIetfOauthUmaTicketResponseModeEnum.PERMISSIONS,
        )
    )

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
