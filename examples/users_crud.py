import asyncio
import uuid

from _common import auth

from pykeycloak.providers.payloads import (
    CreateUserPayload,
    PasswordCredentialsPayload,
    UpdateUserPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
)
from pykeycloak.services.services import UsersService

username = "admin"
password = "password"  # noqa: S105


async def main():
    provider, auth_service = await auth()

    users_service = UsersService(provider)

    # Service account login required for admin operations
    service_account_login = await auth_service.client_login_async()

    print(f"Service account login {service_account_login}")

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
    print(f"Created user: {user_uuid}")

    # Update the user (if creation was successful and returned a user ID)

    # Update user information
    updated_user_payload = UpdateUserPayload(
        first_name="Updated",
        last_name="User",
    )

    await users_service.update_user_async(
        user_id=user_uuid, payload=updated_user_payload
    )

    updated_user = await users_service.get_user_async(user_uuid)

    print(f"Updated user: {updated_user}")

    # Enable/disable user
    enable_payload = UserUpdateEnablePayload(
        enabled=False  # Disable the user
    )

    await users_service.enable_user_async(user_id=user_uuid, payload=enable_payload)
    updated_user = await users_service.get_user_async(user_uuid)

    print(f"Disabled user with ID: {not updated_user.enabled}")

    # Re-enable the user
    enable_payload = UserUpdateEnablePayload(
        enabled=True  # Re-enable the user
    )
    await users_service.enable_user_async(user_id=user_uuid, payload=enable_payload)
    updated_user = await users_service.get_user_async(user_uuid)

    print(f"Enabled user with ID: {updated_user.enabled}")

    # Update user password
    password_payload = UserUpdatePasswordPayload(
        credentials=[
            {"type": "password", "value": "newerpassword123", "temporary": False}
        ]
    )
    await users_service.update_user_password_async(
        user_id=user_uuid, payload=password_payload
    )
    print(f"Updated password for user with ID: {user_uuid}")

    await users_service.delete_user_async(user_id=user_uuid)
    print(f"Deleted user with ID: {user_uuid}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
