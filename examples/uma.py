import asyncio

from _common import service_factory

from pykeycloak.core.enums import UrnIetfOauthUmaTicketResponseModeEnum
from pykeycloak.factories import KeycloakServiceFactory
from pykeycloak.providers.payloads import (
    UMAAuthorizationPayload,
    UserCredentialsLoginPayload,
)

username = "admin"
password = "password"  # noqa: S105


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    result = await factory.auth.user_login_async(  # or user_login_raw_async
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    res = await factory.uma.get_permissions_by_uris_chunks_async(
        payload=UMAAuthorizationPayload(
            audience=None,
            permissions=["/otago/roles#update", "/otago/users#update"],
            subject_token=result.access_token,
            response_mode=UrnIetfOauthUmaTicketResponseModeEnum.PERMISSIONS,
        )
    )

    print(res)


if __name__ == "__main__":
    asyncio.run(main())
