import asyncio

from _common import auth


async def main():
    provider, auth_service = await auth()

    # Get certificates using the access token
    certs = await auth_service.get_certs_async()
    print(f"Certificates: {certs}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
