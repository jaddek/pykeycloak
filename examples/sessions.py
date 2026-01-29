import asyncio

from _common import service_factory

from pykeycloak.providers.payloads import UserCredentialsLoginPayload
from pykeycloak.providers.queries import PaginationQuery
from pykeycloak.services.factory import KeycloakServiceFactory

username = "admin"
password = "password"  # noqa: S105


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    user_login = await factory.auth.user_login_async(
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    print(f"User login {user_login}")

    client_sessions = await factory.sessions.get_client_sessions_async(
        query=PaginationQuery(first=0, max=10)
    )
    print(f"Client sessions: {client_sessions}")

    client_sessions_count = await factory.sessions.get_client_sessions_count_async()
    print(f"Client sessions count: {client_sessions_count}")

    offline_sessions = await factory.sessions.get_offline_sessions_async(
        query=PaginationQuery(first=0, max=10)
    )
    print(f"Offline sessions: {offline_sessions}")

    offline_sessions_count = await factory.sessions.get_offline_sessions_count_async()
    print(f"Offline sessions count: {offline_sessions_count}")

    client_session_stats = await factory.sessions.get_client_session_stats_async()
    print(f"Client session stats: {client_session_stats}")

    logout_result = await factory.sessions.logout_all_users_async()
    print(f"Logout all users result: {logout_result}")


if __name__ == "__main__":
    asyncio.run(main())
