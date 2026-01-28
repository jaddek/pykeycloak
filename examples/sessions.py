import asyncio
import logging
import os

from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.payloads import UserCredentialsLoginPayload
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.providers.queries import PaginationQuery
from pykeycloak.services.services import AuthService, SessionsService

logging.getLogger("pykeycloak").setLevel(logging.DEBUG)

kc_realm = os.getenv("KEYCLOAK_REALM_NAME", "otago")

username = "admin"
password = "password"  # noqa: S105


async def main():
    realm_client = RealmClient.from_env()
    provider = KeycloakInMemoryProviderAsync(
        realm=kc_realm,
        realm_client=realm_client,
    )

    auth_service = AuthService(provider)
    sessions_service = SessionsService(provider)

    service_account_login = await auth_service.client_login_async()

    print(f"Service account login {service_account_login}")

    user_login = await auth_service.user_login_async(
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    print(f"User login {user_login}")

    client_sessions = await sessions_service.get_client_sessions_async(
        query=PaginationQuery(first=0, max=10)
    )
    print(f"Client sessions: {client_sessions}")

    client_sessions_count = await sessions_service.get_client_sessions_count_async()
    print(f"Client sessions count: {client_sessions_count}")

    offline_sessions = await sessions_service.get_offline_sessions_async(
        query=PaginationQuery(first=0, max=10)
    )
    print(f"Offline sessions: {offline_sessions}")

    offline_sessions_count = await sessions_service.get_offline_sessions_count_async()
    print(f"Offline sessions count: {offline_sessions_count}")

    client_session_stats = await sessions_service.get_client_session_stats_async()
    print(f"Client session stats: {client_session_stats}")

    logout_result = await sessions_service.logout_all_users_async()
    print(f"Logout all users result: {logout_result}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
