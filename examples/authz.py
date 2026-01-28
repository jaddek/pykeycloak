import asyncio

from _common import auth

from pykeycloak.services.services import AuthzService


async def main():
    provider, auth_service = await auth()

    authz_service = AuthzService(provider)
    # Get client authorization settings with typed representation
    authz_settings = await authz_service.get_client_authz_settings_async()

    authz_settings_raw = await authz_service.get_client_authz_settings_raw_async()

    print(f"Authz settings: {authz_settings}")
    print(f"Authz raw settings: {authz_settings_raw}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
