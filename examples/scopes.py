import asyncio

from _common import auth

from pykeycloak.services.services import AuthzScopeService


async def main():
    provider, auth_service = await auth()

    authz_service = AuthzScopeService(provider)

    await auth_service.client_login_async()

    raw_scopes = await authz_service.get_client_authz_scopes_raw_async()
    scopes = await authz_service.get_client_authz_scopes_async()

    print(f"Scopes raw: {raw_scopes}")
    print(f"Scopes objects: {scopes}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
