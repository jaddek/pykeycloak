import asyncio

from _common import service_factory

from pykeycloak.providers.payloads import UserCredentialsLoginPayload
from pykeycloak.services.factory import KeycloakServiceFactory

username = "admin"
password = "password"  # noqa: S105


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    # User login to get user-specific access and refresh tokens
    user_login = await factory.auth.user_login_async(
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    print(f"User login {user_login}")

    # Revoke the refresh token
    # Note: After revocation, the refresh token will no longer be valid
    await factory.auth.revoke_async(refresh_token=user_login.refresh_token)
    print(f"Revoked refresh token: {user_login.refresh_token}")

    # Get a fresh token for the next revocation test
    another_login = await factory.auth.user_login_async(
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    revoked_raw = await factory.auth.revoke_raw_async(
        refresh_token=another_login.refresh_token
    )
    print(
        f"Revoked another refresh token (raw): {another_login.refresh_token}, response: {revoked_raw}"
    )


if __name__ == "__main__":
    asyncio.run(main())
