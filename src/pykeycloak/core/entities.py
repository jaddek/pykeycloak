import os
from dataclasses import dataclass


@dataclass
class RealmClient:
    client_uuid: str
    client_id: str
    client_secret: str | None = None
    is_confidential: bool | None = None

    def __post_init__(self) -> None:
        if not self.client_uuid:
            raise ValueError("client_id is required")

        if not self.client_id:
            raise ValueError("client_name is required")

        if self.is_confidential is None:
            self.is_confidential = self.client_secret is not None

        if self.is_confidential and not self.client_secret:
            raise ValueError("Confidential client requires client_secret")

        if not self.is_confidential and self.client_secret:
            raise ValueError("Public client must not have client_secret")

    def resolve_client_id(self, client_id: str | None = None) -> str:
        return client_id if client_id else self.client_id

    @classmethod
    def from_env(cls) -> "RealmClient":
        client_uuid = os.getenv("KEYCLOAK_REALM_CLIENT_UUID")
        client_id = os.getenv("KEYCLOAK_REALM_CLIENT_ID")
        client_secret = os.getenv("KEYCLOAK_REALM_CLIENT_SECRET")

        if not client_uuid:
            raise OSError("KEYCLOAK_REALM_CLIENT_ID is required")

        if not client_id:
            raise OSError("KEYCLOAK_REALM_CLIENT_NAME is required")

        return cls(
            client_uuid=client_uuid,
            client_id=client_id,
            client_secret=client_secret,
        )
