import asyncio

from _common import default_realm_client, get_keycloak

username = "admin"
password = "password"  # noqa: S105


async def main():
    keycloak = get_keycloak(default_realm_client)

    await keycloak.auth.client_login_async()

    print(await keycloak.well_known.get_certs_async())


if __name__ == "__main__":
    asyncio.run(main())
