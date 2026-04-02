# SPDX-License-Identifier: MIT
from unittest.mock import AsyncMock, MagicMock

import pytest

from pykeycloak.core.headers import HeadersFactory
from pykeycloak.core.realm import RealmClient
from pykeycloak.providers._base import KeycloakProviderBase

VALID_UUID = "550e8400-e29b-41d4-a716-446655440000"
REALM = "myrealm"
CLIENT_ID = "my-client"
CLIENT_SECRET = "my-secret"


@pytest.fixture
def realm_client():
    return RealmClient(
        realm_name=REALM,
        client_uuid=VALID_UUID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )


@pytest.fixture
def mock_kc_client():
    client = MagicMock()
    client.base_url = "https://keycloak.example.com"
    client.build_full_url = MagicMock(
        side_effect=lambda path, query="": f"https://keycloak.example.com{path}?{query}"
    )
    client.request_async = AsyncMock(return_value=MagicMock())
    return client


@pytest.fixture
def base(realm_client, mock_kc_client):
    return KeycloakProviderBase(
        realm_client=realm_client,
        kc_headers=HeadersFactory(),
        kc_client=mock_kc_client,
    )


@pytest.fixture
def mock_access_token():
    return AsyncMock(return_value="test-access-token")
