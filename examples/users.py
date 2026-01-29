import asyncio
import uuid

from _common import service_factory

from pykeycloak.factories import KeycloakServiceFactory
from pykeycloak.providers.payloads import (
    CreateUserPayload,
    PasswordCredentialsPayload,
)
from pykeycloak.providers.queries import GetUsersQuery

username = "admin"
password = "password"  # noqa: S105


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    # Get all users with pagination
    users = await factory.users.get_users_async(query=GetUsersQuery(first=0, max=10))
    print(f"Number of users: {len(list(users))}")

    # Get users count
    users_count = await factory.users.get_users_count_async()
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

    user_uuid = await factory.users.create_user_async(payload=new_user_payload)
    print(f"Created user: {new_user_payload.id}")

    specific_user = await factory.users.get_user_async(user_id=user_uuid)
    print(f"Specific user: {specific_user}")


if __name__ == "__main__":
    asyncio.run(main())
