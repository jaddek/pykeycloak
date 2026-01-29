import asyncio

from _common import service_factory

from pykeycloak.factories import KeycloakServiceFactory


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    # Get certificates using the access token
    certs = await factory.auth.get_certs_async()
    print(f"Certificates: {certs}")


if __name__ == "__main__":
    asyncio.run(main())
