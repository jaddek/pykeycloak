import asyncio
from time import time

from _common import service_factory

from pykeycloak.providers.payloads import RolePayload, UserCredentialsLoginPayload
from pykeycloak.services.factory import KeycloakServiceFactory

username = "admin"
password = "password"  # noqa: S105

prefix_for_updated_role = str(time())


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    user_login = await factory.auth.user_login_async(
        payload=UserCredentialsLoginPayload(
            username=username,
            password=password,
        )
    )

    print(f"User login {user_login}")

    # Get all client roles
    client_roles = await factory.roles.get_client_roles_async()
    print(f"Client roles: {client_roles}")

    # Get client roles raw
    client_roles_raw = await factory.roles.get_client_roles_raw_async()
    print(f"Client roles raw: {client_roles_raw}")

    # Create a new role
    new_role_payload = RolePayload(
        name="test-role",
        description="Test role for demonstration",
    )

    created_role = await factory.roles.create_role_async(payload=new_role_payload)
    print(f"Created role: {created_role}")

    # Get role by name
    role_by_name = await factory.roles.get_role_by_name_async(role_name="test-role")
    print(f"Role by name: {role_by_name}")

    # Get role ID by name
    role_id = await factory.roles.get_role_id_async(role_name="test-role")
    print(f"Role ID: {role_id}")

    # Get role by name raw
    role_by_name_raw = await factory.roles.get_role_by_name_raw_async(
        role_name="test-role"
    )
    print(f"Role by name raw: {role_by_name_raw}")

    # Get the role ID to use for update
    role_data = await factory.roles.get_role_by_name_raw_async(role_name="test-role")
    role_id_str = role_data.get("id")

    if role_id_str:
        # Update the role by id
        updated_role_payload = RolePayload(
            name=new_role_payload.name,
            description="Updated test role for demonstration 1s"
            + prefix_for_updated_role,
        )

        updated_role = await factory.roles.update_role_by_name_async(
            role_name=new_role_payload.name,
            payload=updated_role_payload,
        )
        print(f"Updated role: {updated_role}")

    # Get all users to pick one for role assignment
    users = await factory.users.get_users_async()

    if users and len(users) > 0:
        first_user = users[0][0] if isinstance(users[0], list) else users[0]
        user_id = first_user.id

        assign_result = await factory.roles.assign_client_role_async(
            user_id=user_id,
            roles=[role_id],
        )
        print(f"Assigned role to user: {assign_result}")

        user_roles = await factory.roles.get_user_roles_async(user_id=user_id)
        print(f"User roles: {user_roles}")

        # Get client roles of the user
        client_roles_of_user = await factory.roles.get_client_roles_of_user_async(
            user_id=user_id
        )
        print(f"Client roles of user: {client_roles_of_user}")

        # Get composite client roles of user
        composite_roles = await factory.roles.get_composite_client_roles_of_user_async(
            user_id=user_id
        )
        print(f"Composite client roles of user: {composite_roles}")

        # Get available client roles of user
        available_roles = await factory.roles.get_available_client_roles_of_user_async(
            user_id=user_id
        )
        print(f"Available client roles of user: {available_roles}")

    # Delete the role by name
    await factory.roles.delete_role_by_name_async(role_name="test-role")


if __name__ == "__main__":
    asyncio.run(main())
