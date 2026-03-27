import asyncio

from _common import default_realm_client, get_keycloak


async def main():
    keycloak = get_keycloak(default_realm_client)

    await keycloak.auth.client_login_async()

    # Get all permissions
    permissions = await keycloak.authz_permission.get_permissions_async()
    print(f"Permissions: {permissions}")
    print(f"Number of permissions: {len(permissions)}")

    # Get all permissions raw
    permissions_raw = await keycloak.authz_permission.get_permissions_raw_async()
    print(f"Permissions raw: {permissions_raw}")

    # Example of creating a permission (resource-based)
    # resource_based_permission_payload = PermissionPayload(
    #     name="test-resource-permission",
    #     type="resource",
    #     resources=["YOUR_RESOURCE_ID_HERE"],
    #     scopes=["YOUR_SCOPE_ID_HERE"],
    #     policies=["YOUR_POLICY_ID_HERE"],
    # )
    #
    # created_resource_permission = await keycloak.permissions.create_client_authz_permission_based_on_resource_async(
    #     payload=resource_based_permission_payload
    # )
    # print(f"Created resource-based permission: {created_resource_permission}")

    # Example of creating a permission (scope-based)
    # scope_based_permission_payload = PermissionPayload(
    #     name="test-scope-permission",
    #     type="scope",
    #     resources=["YOUR_RESOURCE_ID_HERE"],
    #     scopes=["YOUR_SCOPE_ID_HERE"],
    #     policies=["YOUR_POLICY_ID_HERE"],
    # )
    #
    # created_scope_permission = await keycloak.permissions.create_client_authz_permission_based_on_scope_async(
    #     payload=scope_based_permission_payload
    # )
    # print(f"Created scope-based permission: {created_scope_permission}")

    # Example of updating permission scopes
    # This requires an existing permission ID
    # update_scopes_payload = PermissionScopesPayload(
    #     scopes=["YOUR_NEW_SCOPE_ID_HERE"]
    # )
    #
    # if permissions:
    #     first_permission = permissions[0] if isinstance(permissions[0], dict) else None
    #     if first_permission and 'id' in first_permission:
    #         first_permission_id = first_permission['id']
    #         updated_permission = await keycloak.permissions.update_permission_scopes_async(
    #             permission_id=first_permission_id,
    #             payload=update_scopes_payload
    #         )
    #         print(f"Updated permission: {updated_permission}")

    # Example of deleting a permission
    # This requires an existing permission ID
    # if permissions:
    #     first_permission = permissions[0] if isinstance(permissions[0], dict) else None
    #     if first_permission and 'id' in first_permission:
    #         first_permission_id = first_permission['id']
    #         deleted_permission = await keycloak.permissions.delete_permission_async(
    #             permission_id=first_permission_id
    #         )
    #         print(f"Deleted permission with ID: {first_permission_id}")


if __name__ == "__main__":
    asyncio.run(main())
