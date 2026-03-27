import asyncio
import uuid

from _common import default_realm_client, get_keycloak

from pykeycloak.providers.payloads import ResourcePayload


async def main():
    keycloak = get_keycloak(default_realm_client)

    await keycloak.auth.client_login_async()
    # Get all authz_resource
    authz_resource = await keycloak.authz_resource.get_resources_async()
    print(f"authz_resource: {authz_resource}")
    print(f"Number of authz_resource: {len(authz_resource)}")

    # Get all authz_resource raw
    authz_resource_raw = await keycloak.authz_resource.get_resources_raw_async()
    print(f"authz_resource raw: {authz_resource_raw}")

    id = str(uuid.uuid4())
    # Create a new resource
    new_resource_payload = ResourcePayload(
        id=id,
        name="test-resource" + id,
        display_name="test-resource" + id,
        type="http",
        uris=["/otago/roles"],
        scopes=[{"name": "view"}, {"name": "update"}],
    )

    created_resource = await keycloak.authz_resource.create_resource_async(
        payload=new_resource_payload
    )
    print(f"Created resource: {created_resource}")

    # Get resource by ID if creation was successful
    resource = await keycloak.authz_resource.get_resource_by_id_async(resource_id=id)
    print(f"Resource by ID: {resource}")

    # Get resource permissions
    resource_permissions = await keycloak.authz_resource.get_resource_permissions_async(
        resource_id=id
    )
    print(f"Resource permissions: {resource_permissions}")

    # Note: Deleting the resource is commented out to prevent accidental deletion
    # Uncomment if you want to test deletion
    # await keycloak.authz_resource.delete_resource_by_id_async(resource_id=resource_id)
    # print(f"Deleted resource with ID: {resource_id}")


if __name__ == "__main__":
    asyncio.run(main())
