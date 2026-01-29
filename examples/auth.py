import asyncio

from _common import service_factory

from pykeycloak.providers.payloads import (
    UserCredentialsLoginPayload,
)
from pykeycloak.services.factory import KeycloakServiceFactory

username = "admin"
password = "password"  # noqa: S105


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    ## device login flow
    result = await factory.auth.auth_device_async()  # noqa: F841

    print(result)

    ## User login
    user_tokens = (
        await factory.auth.user_login_async(  # or user_login_raw_async #noqa: F841
            payload=UserCredentialsLoginPayload(
                username=username,
                password=password,
            )
        )
    )

    ## getting user info
    result = await factory.auth.get_user_info_async(  # noqa: F841
        access_token=user_tokens.access_token
    )

    ## logout
    result = await factory.auth.logout_async(user_tokens.refresh_token)  # noqa: F841


if __name__ == "__main__":
    asyncio.run(main())
