import asyncio

from _common import default_realm_client, get_keycloak

from pykeycloak.providers.payloads import (
    SSOLoginPayload,
)


async def main():
    keycloak = get_keycloak(default_realm_client)

    payload = SSOLoginPayload(
        redirect_uri="http://localhost:8000/auth/callback",
        client_id="SSO",
        scopes="openid",
        state="1234567890",
    )

    redirect_url = keycloak.auth.get_redirect_code_url(payload=payload)

    print(redirect_url)


if __name__ == "__main__":
    asyncio.run(main())
