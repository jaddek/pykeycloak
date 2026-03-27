import asyncio

from _common import default_realm_client, get_keycloak


async def main():
    keycloak = get_keycloak(default_realm_client)

    await keycloak.auth.client_login_async()
    # Get client authorization settings with typed representation
    authz_settings = await keycloak.authz.get_client_authz_settings_async()

    authz_settings_raw = await keycloak.authz.get_client_authz_settings_raw_async()

    print(f"Authz settings: {authz_settings}")
    print(f"Authz raw settings: {authz_settings_raw}")


if __name__ == "__main__":
    asyncio.run(main())
