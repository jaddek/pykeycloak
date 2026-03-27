# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import base64
from typing import Self

from pykeycloak.core.helpers import getenv_required
from pykeycloak.core.validations.uuid import is_uuid


class RealmClient:
    def __init__(
        self,
        realm_name: str,
        client_uuid: str,
        client_id: str,
        client_secret: str | None = None,
    ) -> None:
        if not client_uuid or not client_id:
            raise ValueError("client_uuid and client_id are required")

        self.realm_name = realm_name
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

        realm_name = getenv_required(f"KEYCLOAK_REALM_{client_kw}_REALM_NAME")
        uuid = getenv_required(f"KEYCLOAK_REALM_{client_kw}_CLIENT_UUID")
        cid = getenv_required(f"KEYCLOAK_REALM_{client_kw}_CLIENT_ID")
        secret = getenv_required(f"KEYCLOAK_REALM_{client_kw}_CLIENT_SECRET")

        if not all([uuid, cid, realm_name]):
            raise RuntimeError(
                f"Required Keycloak environment variables for {client_kw} are missing"
            )

        if not uuid or not is_uuid(uuid):
            raise RuntimeError(f"Client uuid {uuid} has invalid format. Expected UUID")

        return cls(
            realm_name=realm_name, client_uuid=uuid, client_id=cid, client_secret=secret
        )

    def __str__(self) -> str:
        return f"RealmClient(client_id='{self.client_id}')"

    def __repr__(self) -> str:
        return (
            f"RealmClient(id='{self.client_id}', "
            f"uuid='{self.client_uuid}', "
            f"confidential={self.is_confidential})"
        )
