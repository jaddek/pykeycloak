# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>
from mypyc.ir.class_ir import NamedTuple

from .factories import KeycloakServiceFactory


class KeycloakClientInstanceKey(NamedTuple):
    realm_name: str
    realm_client_name: str


class FactoryRegistry:
    def __init__(self) -> None:
        self._map: dict[KeycloakClientInstanceKey, KeycloakServiceFactory] = {}

    def register(
        self, instance_key: KeycloakClientInstanceKey, factory: KeycloakServiceFactory
    ) -> None:
        self._map[instance_key] = factory

    def get(self, instance_key: KeycloakClientInstanceKey) -> KeycloakServiceFactory:
        instance = self._map.get(instance_key)
        if not instance:
            raise ValueError(
                f"Provider for realm '{instance_key.realm_name}' and client '{instance_key.realm_client_name}' not found"
            )

        return instance

    async def close_all(self) -> None:
        for factory in self._map.values():
            await factory.provider.close()

    @staticmethod
    def from_realm(
        instance_key: KeycloakClientInstanceKey, factory: KeycloakServiceFactory
    ) -> "FactoryRegistry":
        registry = FactoryRegistry()
        registry.register(instance_key, factory)

        return registry
