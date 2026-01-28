import asyncio
import logging
import os
import uuid

from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.payloads import ResourcePayload
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.services.services import AuthService, AuthzResourceService

logging.getLogger("pykeycloak").setLevel(logging.DEBUG)

kc_realm = os.getenv("KEYCLOAK_REALM_NAME", "otago")


async def main():
    realm_client = RealmClient.from_env()
    provider = KeycloakInMemoryProviderAsync(
        realm=kc_realm,
        realm_client=realm_client,
    )

    auth_service = AuthService(provider)
    authz_resource_service = AuthzResourceService(provider)

    # Service account login required for admin operations
    service_account_login = await auth_service.client_login_async()

    print(f"Service account login {service_account_login}")

    # Get all resources
    resources = await authz_resource_service.get_resources_async()
    print(f"Resources: {resources}")
    print(f"Number of resources: {len(resources)}")

    # Get all resources raw
    resources_raw = await authz_resource_service.get_resources_raw_async()
    print(f"Resources raw: {resources_raw}")

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

    created_resource = await authz_resource_service.create_resource_async(
        payload=new_resource_payload
    )
    print(f"Created resource: {created_resource}")

    # Get resource by ID if creation was successful
    resource = await authz_resource_service.get_resource_by_id_async(resource_id=id)
    print(f"Resource by ID: {resource}")

    # Get resource permissions
    resource_permissions = await authz_resource_service.get_resource_permissions_async(
        resource_id=id
    )
    print(f"Resource permissions: {resource_permissions}")

    # Note: Deleting the resource is commented out to prevent accidental deletion
    # Uncomment if you want to test deletion
    # await authz_resource_service.delete_resource_by_id_async(resource_id=resource_id)
    # print(f"Deleted resource with ID: {resource_id}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
