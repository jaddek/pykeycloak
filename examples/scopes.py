import asyncio

from _common import service_factory

from pykeycloak.services.factory import KeycloakServiceFactory


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    raw_scopes = await factory.authz_scope.get_client_authz_scopes_raw_async()
    scopes = await factory.authz_scope.get_client_authz_scopes_async()

    print(f"Scopes raw: {raw_scopes}")
    print(f"Scopes objects: {scopes}")


if __name__ == "__main__":
    asyncio.run(main())
