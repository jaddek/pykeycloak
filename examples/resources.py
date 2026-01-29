import asyncio
import uuid

from _common import service_factory

from pykeycloak.providers.payloads import ResourcePayload
from pykeycloak.services.factory import KeycloakServiceFactory


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    # Get all authz_resource
    authz_resource = await factory.authz_resource.get_resources_async()
    print(f"authz_resource: {authz_resource}")
    print(f"Number of authz_resource: {len(authz_resource)}")

    # Get all authz_resource raw
    authz_resource_raw = await factory.authz_resource.get_resources_raw_async()
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

    created_resource = await factory.authz_resource.create_resource_async(
        payload=new_resource_payload
    )
    print(f"Created resource: {created_resource}")

    # Get resource by ID if creation was successful
    resource = await factory.authz_resource.get_resource_by_id_async(resource_id=id)
    print(f"Resource by ID: {resource}")

    # Get resource permissions
    resource_permissions = await factory.authz_resource.get_resource_permissions_async(
        resource_id=id
    )
    print(f"Resource permissions: {resource_permissions}")

    # Note: Deleting the resource is commented out to prevent accidental deletion
    # Uncomment if you want to test deletion
    # await factory.authz_resource.delete_resource_by_id_async(resource_id=resource_id)
    # print(f"Deleted resource with ID: {resource_id}")


if __name__ == "__main__":
    asyncio.run(main())
