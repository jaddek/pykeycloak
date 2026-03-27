import asyncio

from _common import default_realm_client, get_keycloak


async def main():
    keycloak = get_keycloak(default_realm_client)

    await keycloak.auth.client_login_async()

    raw_scopes = await keycloak.authz_scope.get_client_authz_scopes_raw_async()
    scopes = await keycloak.authz_scope.get_client_authz_scopes_async()

    print(f"Scopes raw: {raw_scopes}")
    print(f"Scopes objects: {scopes}")


if __name__ == "__main__":
    asyncio.run(main())
