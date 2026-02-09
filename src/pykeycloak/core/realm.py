# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import base64
import os
from dataclasses import dataclass
from typing import Self


@dataclass(frozen=True, slots=True, kw_only=True)
class Realm:
    name: str


class RealmClient:
    def __init__(
        self, client_uuid: str, client_id: str, client_secret: str | None = None
    ) -> None:
        if not client_uuid or not client_id:
            raise ValueError("client_uuid and client_id are required")

        self.client_uuid = client_uuid
        self.client_id = client_id
        self.client_secret = client_secret
        self.is_confidential = client_secret is not None

    def base64_encoded_client_secret(self) -> str:
        if not self.client_secret:
            raise AttributeError("Public client has no secret for Basic Auth")

        auth_str = f"{self.client_id}:{self.client_secret}"
        return base64.b64encode(auth_str.encode()).decode()

    def resolve_id(self, override_id: str | None = None) -> str:
        return override_id or self.client_id

    @classmethod
    def from_env(cls, client_name: str) -> Self:
        client_kw = client_name.upper()
        uuid = os.getenv(f"KEYCLOAK_REALM_{client_kw}_CLIENT_UUID")
        cid = os.getenv(f"KEYCLOAK_REALM_{client_kw}_CLIENT_ID")
        secret = os.getenv(f"KEYCLOAK_REALM_{client_kw}_CLIENT_SECRET")

        if not uuid or not cid:
            raise RuntimeError(
                f"Required Keycloak environment variables for {client_kw} are missing"
            )

        return cls(client_uuid=uuid, client_id=cid, client_secret=secret)

    def __str__(self) -> str:
        return f"RealmClient(client_id='{self.client_id}')"

    def __repr__(self) -> str:
        return (
            f"RealmClient(id='{self.client_id}', "
            f"uuid='{self.client_uuid}', "
            f"confidential={self.is_confidential})"
        )
