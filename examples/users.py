import asyncio
import logging
import os
import uuid

from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.payloads import (
    CreateUserPayload,
    PasswordCredentialsPayload,
    UserCredentialsLoginPayload,
)
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.providers.queries import GetUsersQuery
from pykeycloak.services.services import AuthService, UsersService

logging.basicConfig(
    level=logging.DEBUG, format="%(name)s - %(levelname)s - %(message)s"
)
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
    users_service = UsersService(provider)

    # Service account login required for admin operations
    await auth_service.client_login_async()

    # User login for user-specific operations
    await auth_service.user_login_async(
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    # Get all users with pagination
    users = await users_service.get_users_async(query=GetUsersQuery(first=0, max=10))
    print(f"Number of users: {len(list(users))}")

    # Get users count
    users_count = await users_service.get_users_count_async()
    print(f"Users count: {users_count}")

    # Example of creating a new user (uncomment if you want to test creation)
    new_user_payload = CreateUserPayload(
        username="testuser" + uuid.uuid4().hex,
        email="testuser+" + uuid.uuid4().hex + "@example.com",
        first_name="Test",
        last_name="User",
        enabled=True,
        credentials=[
            PasswordCredentialsPayload(
                value="hello jazz",
            )
        ],
    )

    user_uuid = await users_service.create_user_async(payload=new_user_payload)
    print(f"Created user: {new_user_payload.id}")

    specific_user = await users_service.get_user_async(user_id=user_uuid)
    print(f"Specific user: {specific_user}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
