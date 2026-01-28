import asyncio
import logging
import os
from time import time

from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.payloads import RolePayload, UserCredentialsLoginPayload
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.services.services import AuthService, RolesService, UsersService

logging.getLogger("pykeycloak").setLevel(logging.DEBUG)

kc_realm = os.getenv("KEYCLOAK_REALM_NAME", "otago")

username = "admin"
password = "password"  # noqa: S105

prefix_for_updated_role = str(time())


async def main():
    realm_client = RealmClient.from_env()
    provider = KeycloakInMemoryProviderAsync(
        realm=kc_realm,
        realm_client=realm_client,
    )

    auth_service = AuthService(provider)
    roles_service = RolesService(provider)
    users_service = UsersService(provider)

    service_account_login = await auth_service.client_login_async()

    print(f"Service account login {service_account_login}")

    user_login = await auth_service.user_login_async(
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    print(f"User login {user_login}")

    # Get all client roles
    client_roles = await roles_service.get_client_roles_async()
    print(f"Client roles: {client_roles}")

    # Get client roles raw
    client_roles_raw = await roles_service.get_client_roles_raw_async()
    print(f"Client roles raw: {client_roles_raw}")

    # Create a new role
    new_role_payload = RolePayload(
        name="test-role",
        description="Test role for demonstration",
    )

    created_role = await roles_service.create_role_async(payload=new_role_payload)
    print(f"Created role: {created_role}")

    # Get role by name
    role_by_name = await roles_service.get_role_by_name_async(role_name="test-role")
    print(f"Role by name: {role_by_name}")

    # Get role ID by name
    role_id = await roles_service.get_role_id_async(role_name="test-role")
    print(f"Role ID: {role_id}")

    # Get role by name raw
    role_by_name_raw = await roles_service.get_role_by_name_raw_async(
        role_name="test-role"
    )
    print(f"Role by name raw: {role_by_name_raw}")

    # Get the role ID to use for update
    role_data = await roles_service.get_role_by_name_raw_async(role_name="test-role")
    role_id_str = role_data.get("id")

    if role_id_str:
        # Update the role by id
        updated_role_payload = RolePayload(
            name=new_role_payload.name,
            description="Updated test role for demonstration 1s"
            + prefix_for_updated_role,
        )

        updated_role = await roles_service.update_role_by_name_async(
            role_name=new_role_payload.name,
            payload=updated_role_payload,
        )
        print(f"Updated role: {updated_role}")

    # Get all users to pick one for role assignment
    users = await users_service.get_users_async()

    if users and len(users) > 0:
        first_user = users[0][0] if isinstance(users[0], list) else users[0]
        user_id = first_user.get("id")

        assign_result = await roles_service.assign_client_role_async(
            user_id=user_id,
            roles=[role_id],
        )
        print(f"Assigned role to user: {assign_result}")

        user_roles = await roles_service.get_user_roles_async(user_id=user_id)
        print(f"User roles: {user_roles}")

        # Get client roles of the user
        client_roles_of_user = await roles_service.get_client_roles_of_user_async(
            user_id=user_id
        )
        print(f"Client roles of user: {client_roles_of_user}")

        # Get composite client roles of user
        composite_roles = await roles_service.get_composite_client_roles_of_user_async(
            user_id=user_id
        )
        print(f"Composite client roles of user: {composite_roles}")

        # Get available client roles of user
        available_roles = await roles_service.get_available_client_roles_of_user_async(
            user_id=user_id
        )
        print(f"Available client roles of user: {available_roles}")

    # Delete the role by name
    await roles_service.delete_role_by_name_async(role_name="test-role")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
