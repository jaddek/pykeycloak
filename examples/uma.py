import asyncio

from _common import default_realm_client, get_keycloak, get_user_credentials

from pykeycloak.core.enums import UrnIetfOauthUmaTicketResponseModeEnum
from pykeycloak.providers.payloads import (
    UMAAuthorizationPayload,
)


async def main():
    keycloak = get_keycloak(default_realm_client)

    result = await keycloak.auth.user_login_async(  # or user_login_raw_async
        payload=get_user_credentials()
    )

    res = await keycloak.uma.get_permissions_by_uris_chunks_async(
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
