import asyncio
import logging
import os

from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.providers import KeycloakInMemoryProviderAsync
from pykeycloak.services.services import AuthService, ClientsService

logging.basicConfig(level=logging.DEBUG)
kc_realm = os.getenv("KEYCLOAK_REALM_NAME", "otago")

username = "admin"
password = "password"  # noqa: S105


async def main():
    realm_client = RealmClient.from_env()
    provider = KeycloakInMemoryProviderAsync(
        realm=kc_realm,
        realm_client=realm_client,
    )

    auth_service = AuthService(provider)
    clients_service = ClientsService(provider)

    service_account_login = await auth_service.client_login_async()

    print(f"Service account login {service_account_login}")

    # Get specific client raw
    client_raw = await clients_service.get_client_raw_async()
    print(f"Client raw: {client_raw}")

    # Get all clients with typed representation
    clients = await clients_service.get_clients_async()
    print(f"Clients: {clients}")
    print(f"Number of clients: {len(clients)}")

    if clients:
        first_client = clients[0]
        print(f"First client ID: {first_client.id}")
        print(f"First client name: {first_client.name}")
        print(f"First client client_id: {first_client.client_id}")
        print(f"First client enabled: {first_client.enabled}")

    # Get all clients raw
    clients_raw = await clients_service.get_clients_raw_async()
    print(f"Clients raw length: {len(clients_raw)}")

    # Get specific client with typed representation
    client = await clients_service.get_client_async()
    print(f"Specific client: {client}")
    print(f"Specific client name: {client.name}")
    print(f"Specific client client_id: {client.client_id}")
    print(f"Specific client protocol: {client.protocol}")

    await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
