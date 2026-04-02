import asyncio

from _common import default_realm_client, get_keycloak


async def main():
    keycloak = get_keycloak(default_realm_client)

    await keycloak.auth.client_login_async()

    # Get certificates using the access token
    certs = await keycloak.well_known.get_certs_async()
    print(f"Certificates: {certs}")

    #
    config = await keycloak.well_known.get_uma2_configuration_async()
    print(f"Uma2 configuration: {config}")

    #
    config = await keycloak.well_known.get_openid_configuration_async()
    print(f"Openid configuration: {config}")


if __name__ == "__main__":
    asyncio.run(main())
