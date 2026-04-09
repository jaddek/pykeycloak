import asyncio
import logging

from _common import default_realm_client, get_keycloak

logging.basicConfig(
    level=logging.DEBUG, format="%(name)s - %(levelname)s - %(message)s"
)


async def main():
    keycloak = get_keycloak(default_realm_client)

    await keycloak.auth.client_login_async()
    result = await keycloak.users.impersonate_async(
        "b8b1a406-b8b1-78e6-a0e7-618f997aa57c"
    )  # noqa: F841

    print("-----")
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
