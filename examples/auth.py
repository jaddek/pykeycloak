import asyncio
import logging

from _common import default_realm_client, get_keycloak

from pykeycloak.providers.payloads import (
    UserCredentialsLoginPayload,
)

logging.basicConfig(
    level=logging.DEBUG, format="%(name)s - %(levelname)s - %(message)s"
)

username = "admin"
password = "password"  # noqa: S105


async def main():
    keycloak = get_keycloak(default_realm_client)

    await keycloak.auth.client_login_async()
    ## device login flow
    result = await keycloak.auth.auth_device_async()  # noqa: F841

    print(result)

    ## User login
    user_tokens = (
        await keycloak.auth.user_login_async(  # or user_login_raw_async #noqa: F841
            payload=UserCredentialsLoginPayload(
                username=username,
                password=password,
            )
        )
    )

    ## getting user info
    result = await keycloak.auth.get_user_info_async(  # noqa: F841
        access_token=user_tokens.access_token
    )

    ## logout
    result = await keycloak.auth.logout_async(user_tokens.refresh_token)  # noqa: F841


if __name__ == "__main__":
    asyncio.run(main())
