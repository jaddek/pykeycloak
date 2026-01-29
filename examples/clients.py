import asyncio

from _common import service_factory

from pykeycloak.factories import KeycloakServiceFactory


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    # Get specific client raw
    client_raw = await factory.clients.get_client_raw_async()
    print(f"Client raw: {client_raw}")

    # Get all clients with typed representation
    clients = await factory.clients.get_clients_async()
    print(f"Clients: {clients}")
    print(f"Number of clients: {len(clients)}")

    if clients:
        first_client = clients[0]
        print(f"First client ID: {first_client.id}")
        print(f"First client name: {first_client.name}")
        print(f"First client client_id: {first_client.client_id}")
        print(f"First client enabled: {first_client.enabled}")

    # Get all clients raw
    clients_raw = await factory.clients.get_clients_raw_async()
    print(f"Clients raw length: {len(clients_raw)}")

    # Get specific client with typed representation
    client = await factory.clients.get_client_async()
    print(f"Specific client: {client}")
    print(f"Specific client name: {client.name}")
    print(f"Specific client client_id: {client.client_id}")
    print(f"Specific client protocol: {client.protocol}")


if __name__ == "__main__":
    asyncio.run(main())
