import asyncio

from _common import default_realm_client, get_keycloak, get_user_credentials

from pykeycloak.providers.queries import PaginationQuery


async def main():
    keycloak = get_keycloak(default_realm_client)

    user_login = await keycloak.auth.user_login_async(payload=get_user_credentials())

    print(f"User login {user_login}")

    client_sessions = await keycloak.sessions.get_client_sessions_async(
        query=PaginationQuery(first=0, max=10)
    )
    print(f"Client sessions: {client_sessions}")

    client_sessions_count = await keycloak.sessions.get_client_sessions_count_async()
    print(f"Client sessions count: {client_sessions_count}")

    offline_sessions = await keycloak.sessions.get_offline_sessions_async(
        query=PaginationQuery(first=0, max=10)
    )
    print(f"Offline sessions: {offline_sessions}")

    offline_sessions_count = await keycloak.sessions.get_offline_sessions_count_async()
    print(f"Offline sessions count: {offline_sessions_count}")

    client_session_stats = await keycloak.sessions.get_client_session_stats_async()
    print(f"Client session stats: {client_session_stats}")

    logout_result = await keycloak.sessions.logout_all_users_async()
    print(f"Logout all users result: {logout_result}")


if __name__ == "__main__":
    asyncio.run(main())
