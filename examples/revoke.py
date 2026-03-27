import asyncio

from _common import default_realm_client, get_keycloak, get_user_credentials


async def main():
    keycloak = get_keycloak(default_realm_client)

    await keycloak.auth.client_login_async()

    # User login to get user-specific access and refresh tokens
    user_login = await keycloak.auth.user_login_async(payload=get_user_credentials())

    print(f"User login {user_login}")

    # Revoke the refresh token
    # Note: After revocation, the refresh token will no longer be valid
    await keycloak.auth.revoke_async(refresh_token=user_login.refresh_token)
    print(f"Revoked refresh token: {user_login.refresh_token}")

    # Get a fresh token for the next revocation test
    another_login = await keycloak.auth.user_login_async(payload=get_user_credentials())

    revoked_raw = await keycloak.auth.revoke_raw_async(
        refresh_token=another_login.refresh_token
    )
    print(
        f"Revoked another refresh token (raw): {another_login.refresh_token}, response: {revoked_raw}"
    )


if __name__ == "__main__":
    asyncio.run(main())
