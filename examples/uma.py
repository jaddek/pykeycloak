import asyncio

from _common import service_factory

from pykeycloak.core.enums import UrnIetfOauthUmaTicketResponseModeEnum
from pykeycloak.factories import KeycloakServiceFactory
from pykeycloak.providers.payloads import (
    UMAAuthorizationPayload,
    UserCredentialsLoginPayload,
)

username = "admin"
password = "password"  # noqa: S105


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    result = await factory.auth.user_login_async(  # or user_login_raw_async
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    ## response with available permissions (could be 401 if no permissions)
    ## this request should be batched as KC has limitations on amount of permissions it could check at one request
    await factory.uma.get_uma_permissions_async(
        payload=UMAAuthorizationPayload(
            audience=None,
            permissions={"/otago/users": ["view"]},
            subject_token=result.access_token,
            response_mode=UrnIetfOauthUmaTicketResponseModeEnum.PERMISSIONS,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
