# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from mypyc.ir.class_ir import NamedTuple

from .core.protocols import KeycloakServiceFactoryProtocol
from .factories import KeycloakServiceFactory


class KeycloakClientInstanceKey(NamedTuple):
    realm_name: str
    realm_client_name: str


class KeycloakWellKnownClientInstanceKey(KeycloakClientInstanceKey):
    realm_name: str
    realm_client_name: str


class FactoryRegistry:
    def __init__(self) -> None:
        self._map: dict[KeycloakClientInstanceKey, KeycloakServiceFactory] = {}

    def register(
        self,
        instance_key: KeycloakClientInstanceKey,
        factory: KeycloakServiceFactory,
    ) -> None:
        if instance_key in self._map:
            raise ValueError(
                f"Factory for realm '{instance_key.realm_name}' and client "
                f"'{instance_key.realm_client_name}' is already registered."
            )

        self._map[instance_key] = factory

    def unregister(self, instance_key: KeycloakClientInstanceKey) -> None:
        if instance_key not in self._map:
            raise KeyError(
                f"No factory found for realm '{instance_key.realm_name}' and "
                f"client '{instance_key.realm_client_name}'."
            )
        del self._map[instance_key]

    def get(
        self, instance_key: KeycloakClientInstanceKey
    ) -> KeycloakServiceFactoryProtocol:
        instance = self._map.get(instance_key)
        if not instance:
            raise ValueError(
                f"Provider for realm '{instance_key.realm_name}' and client '{instance_key.realm_client_name}' not found"
            )

        return instance

    async def close_all(self) -> None:
        errors: list[tuple[KeycloakClientInstanceKey, Exception]] = []

        for key, factory in self._map.items():
            try:
                await factory.provider.close_connection()
            except Exception as e:
                errors.append((key, e))

        if errors:
            error_details = "; ".join(
                f"realm='{k.realm_name}', client='{k.realm_client_name}': {e}"
                for k, e in errors
            )
            raise RuntimeError(f"Errors during close_all: {error_details}")

    @staticmethod
    def from_realm(
        instance_key: KeycloakClientInstanceKey, factory: KeycloakServiceFactory
    ) -> "FactoryRegistry":
        registry = FactoryRegistry()
        registry.register(instance_key, factory)

        return registry
