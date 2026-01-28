import asyncio

from _common import auth

from pykeycloak.providers.payloads import (
    UserCredentialsLoginPayload,
)

username = "admin"
password = "password"  # noqa: S105


async def main():
    provider, auth_service = await auth()

    ## device login flow
    result = await auth_service.auth_device_raw_async()  # noqa: F841

    ## User login
    user_tokens = (
        await auth_service.user_login_async(  # or user_login_raw_async #noqa: F841
            payload=UserCredentialsLoginPayload(
                username=username,
                password=password,
            )
        )
    )

    ## getting user info
    result = await auth_service.get_user_info_async(  # noqa: F841
        access_token=user_tokens.access_token
    )

    ## logout
    result = await auth_service.logout_async(user_tokens.refresh_token)  # noqa: F841

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
