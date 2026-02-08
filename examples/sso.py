import asyncio
import logging

from _common import service_factory

from pykeycloak.factories import KeycloakServiceFactory
from pykeycloak.providers.payloads import (
    AuthRedirectPayload,
)

logging.basicConfig(
    level=logging.DEBUG, format="%(name)s - %(levelname)s - %(message)s"
)


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    payload = AuthRedirectPayload(
        redirect_uri="http://localhost:8000/auth/callback",
        client_id="SSO",
        scopes="openid",
    )

    redirect_url = factory.auth.get_redirect_code_url(payload=payload)

    print(redirect_url)


if __name__ == "__main__":
    asyncio.run(main())
