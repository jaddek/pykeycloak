import asyncio

from _common import auth

from pykeycloak.core.enums import UrnIetfOauthUmaTicketResponseModeEnum
from pykeycloak.providers.payloads import (
    UMAAuthorizationPayload,
    UserCredentialsLoginPayload,
)
from pykeycloak.services.services import UmaService

username = "admin"
password = "password"  # noqa: S105


async def main():
    provider, auth_service = await auth()

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
            audience=result.access_token,  # Using the access token from user login
            permissions={"/otago/users": ["view"]},
            subject_token=result.access_token,
            response_mode=UrnIetfOauthUmaTicketResponseModeEnum.PERMISSIONS,
        )
    )

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
