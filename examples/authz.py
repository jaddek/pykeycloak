import asyncio

from _common import service_factory

from pykeycloak.services.factory import KeycloakServiceFactory


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    # Get client authorization settings with typed representation
    authz_settings = await factory.authz.get_client_authz_settings_async()

    authz_settings_raw = await factory.authz.get_client_authz_settings_raw_async()

    print(f"Authz settings: {authz_settings}")
    print(f"Authz raw settings: {authz_settings_raw}")


if __name__ == "__main__":
    asyncio.run(main())
