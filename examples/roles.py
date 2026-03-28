import asyncio
import uuid
from time import time

from _common import default_realm_client, get_keycloak

from pykeycloak.providers.payloads import RoleAssignPayload, RolePayload

prefix_for_updated_role = str(time())


async def main():
    keycloak = get_keycloak(default_realm_client)

    await keycloak.auth.client_login_async()

    # Get all client roles
    client_roles = await keycloak.roles.get_client_roles_async()
    print(f"Client roles: {client_roles}")

    # Get client roles raw
    client_roles_raw = await keycloak.roles.get_client_roles_raw_async()
    print(f"Client roles raw: {client_roles_raw}")

    # Create a new role
    new_role_payload = RolePayload(
        name="test-role" + uuid.uuid4().hex,
        description="Test role for demonstration",
    )

    created_role = await keycloak.roles.create_role_async(payload=new_role_payload)
    print(f"Created role: {created_role}")

    # Get role by name
    role_by_name = await keycloak.roles.get_role_by_name_async(
        role_name=new_role_payload.name
    )
    print(f"Role by name: {role_by_name}")

    # Get role by name raw
    role_by_name_raw = await keycloak.roles.get_role_by_name_raw_async(
        role_name=new_role_payload.name
    )
    print(f"Role by name raw: {role_by_name_raw}")

    # Get the role ID to use for update
    role_data = await keycloak.roles.get_role_by_name_raw_async(
        role_name=new_role_payload.name
    )
    role_id_str = role_data.get("id")

    if role_id_str:
        # Update the role by id
        updated_role_payload = RolePayload(
            name=new_role_payload.name,
            description="Updated test role for demonstration 1s"
            + prefix_for_updated_role,
        )

        updated_role = await keycloak.roles.update_role_by_name_async(
            role_name=new_role_payload.name,
            payload=updated_role_payload,
        )
        print(f"Updated role: {updated_role}")

    # Get all users to pick one for role assignment
    users, _count = await keycloak.users.get_users_async()

    if users:
        first_user = users[0]
        user_id = first_user.id

        assign_result = await keycloak.roles.assign_role_async(
            user_id=user_id,
            roles=[RoleAssignPayload(name=new_role_payload.name, id=role_id_str)],
        )
        print(f"Assigned role to user: {assign_result}")

        user_roles = await keycloak.roles.get_user_roles_async(user_id=user_id)
        print(f"User roles: {user_roles}")

        # Get client roles of the user
        client_roles_of_user = await keycloak.roles.get_client_roles_of_user_async(
            user_id=user_id
        )
        print(f"Client roles of user: {client_roles_of_user}")

        # Get composite client roles of user
        composite_roles = await keycloak.roles.get_composite_client_roles_of_user_async(
            user_id=user_id
        )
        print(f"Composite client roles of user: {composite_roles}")

        # Get available client roles of user
        available_roles = await keycloak.roles.get_available_client_roles_of_user_async(
            user_id=user_id
        )
        print(f"Available client roles of user: {available_roles}")

    # Delete the role by name
    await keycloak.roles.delete_role_by_name_async(role_name=new_role_payload.name)


if __name__ == "__main__":
    asyncio.run(main())
