import asyncio
import uuid

from _common import default_realm_client, get_keycloak

from pykeycloak.providers.payloads import (
    CreateUserPayload,
    PasswordCredentialsPayload,
)
from pykeycloak.providers.queries import GetUsersQuery


async def main():
    keycloak = get_keycloak(default_realm_client)

    # Get subset of users
    users, count = await keycloak.users.get_users_async(
        query=GetUsersQuery(first=1, max=10)
    )
    print(f"Number of users: {count} and received {len(users)}")

    # Get all of users
    users, count = await keycloak.users.get_all_users_async()
    print(f"Number of users: {count} and received {len(users)}")

    # Get users count
    users_count = await keycloak.users.get_users_count_async()
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

    user_uuid = await keycloak.users.create_user_async(payload=new_user_payload)
    print(f"Created user: {new_user_payload.id}")

    specific_user = await keycloak.users.get_user_async(user_id=user_uuid)
    print(f"Specific user: {specific_user}")


if __name__ == "__main__":
    asyncio.run(main())
