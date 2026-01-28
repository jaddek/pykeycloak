import asyncio

from _common import auth

from pykeycloak.providers.payloads import UserCredentialsLoginPayload

username = "admin"
password = "password"  # noqa: S105


async def main():
    provider, auth_service = await auth()

    # Service account login required to get access to admin operations
    service_account_login = await auth_service.client_login_async()

    print(f"Service account login {service_account_login}")

    # User login to get user-specific access and refresh tokens
    user_login = await auth_service.user_login_async(
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    print(f"User login {user_login}")

    # Revoke the refresh token
    # Note: After revocation, the refresh token will no longer be valid
    await auth_service.revoke_async(refresh_token=user_login.refresh_token)
    print(f"Revoked refresh token: {user_login.refresh_token}")

    # Get a fresh token for the next revocation test
    another_login = await auth_service.user_login_async(
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    revoked_raw = await auth_service.revoke_raw_async(
        refresh_token=another_login.refresh_token
    )
    print(
        f"Revoked another refresh token (raw): {another_login.refresh_token}, response: {revoked_raw}"
    )

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
