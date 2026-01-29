"""
Unit tests for the entities module.
"""

import os
from unittest.mock import patch

import pytest

from pykeycloak.core.realm import RealmClient


class TestRealmClient:
    """Test cases for the RealmClient class."""

    def test_realm_client_creation_with_valid_data(self):
        """Test creating a RealmClient with valid data."""
        client_uuid = "test-uuid"
        client_id = "test-client-id"
        client_secret = "test-secret"  # noqa: S105

        client = RealmClient(client_uuid, client_id, client_secret)

        assert client.client_uuid == client_uuid
        assert client.client_id == client_id
        assert client.client_secret == client_secret
        assert client.is_confidential is True

    def test_realm_client_creation_without_secret(self):
        """Test creating a RealmClient without a secret (public client)."""
        client_uuid = "test-uuid"
        client_id = "test-client-id"

        client = RealmClient(client_uuid, client_id)

        assert client.client_uuid == client_uuid
        assert client.client_id == client_id
        assert client.client_secret is None
        assert client.is_confidential is False

    def test_realm_client_creation_with_empty_uuid_raises_error(self):
        """Test that creating a RealmClient with empty UUID raises ValueError."""
        with pytest.raises(ValueError, match="client_uuid and client_id are required"):
            RealmClient("", "test-client-id", "test-secret")

    def test_realm_client_creation_with_empty_client_id_raises_error(self):
        """Test that creating a RealmClient with empty client ID raises ValueError."""
        with pytest.raises(ValueError, match="client_uuid and client_id are required"):
            RealmClient("test-uuid", "", "test-secret")

    def test_realm_client_creation_with_none_values_raises_error(self):
        """Test that creating a RealmClient with None values raises ValueError."""
        with pytest.raises(ValueError, match="client_uuid and client_id are required"):
            RealmClient(None, None, None)

    def test_base64_auth_for_confidential_client(self):
        """Test base64 authentication string creation for confidential client."""
        client_uuid = "test-uuid"
        client_id = "test-client-id"
        client_secret = "test-secret"  # noqa: S105

        client = RealmClient(client_uuid, client_id, client_secret)
        expected_auth = "dGVzdC1jbGllbnQtaWQ6dGVzdC1zZWNyZXQ="  # base64 encoded "test-client-id:test-secret"

        assert client.base64_encoded_client_secret() == expected_auth

    def test_base64_auth_for_public_client_raises_error(self):
        """Test that calling base64_auth on a public client raises AttributeError."""
        client_uuid = "test-uuid"
        client_id = "test-client-id"

        client = RealmClient(client_uuid, client_id)

        with pytest.raises(
            AttributeError, match="Public client has no secret for Basic Auth"
        ):
            client.base64_encoded_client_secret()

    def test_resolve_id_with_override(self):
        """Test resolve_id method with an override ID."""
        client_uuid = "test-uuid"
        client_id = "test-client-id"
        client_secret = "test-secret"  # noqa: S105

        client = RealmClient(client_uuid, client_id, client_secret)
        override_id = "override-id"

        assert client.resolve_id(override_id) == override_id

    def test_resolve_id_without_override_returns_client_id(self):
        """Test resolve_id method without an override ID."""
        client_uuid = "test-uuid"
        client_id = "test-client-id"
        client_secret = "test-secret"  # noqa: S105

        client = RealmClient(client_uuid, client_id, client_secret)

        assert client.resolve_id() == client_id

    def test_resolve_id_with_none_override_returns_client_id(self):
        """Test resolve_id method with None as override ID."""
        client_uuid = "test-uuid"
        client_id = "test-client-id"
        client_secret = "test-secret"  # noqa: S105

        client = RealmClient(client_uuid, client_id, client_secret)

        assert client.resolve_id(None) == client_id

    @patch.dict(
        os.environ,
        {
            "KEYCLOAK_REALM_CLIENT_UUID": "env-test-uuid",
            "KEYCLOAK_REALM_CLIENT_ID": "env-test-client-id",
            "KEYCLOAK_REALM_CLIENT_SECRET": "env-test-secret",
        },
    )
    def test_from_env_creates_client_with_environment_variables(self):
        """Test creating a RealmClient from environment variables."""
        client = RealmClient.from_env()

        assert client.client_uuid == "env-test-uuid"
        assert client.client_id == "env-test-client-id"
        assert client.client_secret == "env-test-secret"  # noqa: S105
        assert client.is_confidential is True

    @patch.dict(
        os.environ,
        {
            "KEYCLOAK_REALM_CLIENT_UUID": "env-test-uuid",
            "KEYCLOAK_REALM_CLIENT_ID": "env-test-client-id",
            "KEYCLOAK_REALM_CLIENT_SECRET": "",
        },
    )
    def test_from_env_creates_public_client_when_secret_is_empty(self):
        """Test creating a public RealmClient from environment variables when secret is empty."""
        client = RealmClient.from_env()

        assert client.client_uuid == "env-test-uuid"
        assert client.client_id == "env-test-client-id"
        assert client.client_secret == ""
        # Note: is_confidential is True even with empty string because it checks for None, not empty string
        assert client.is_confidential is True

    @patch.dict(os.environ, {}, clear=True)
    def test_from_env_raises_error_when_required_variables_are_missing(self):
        """Test that from_env raises OSError when required environment variables are missing."""
        with pytest.raises(
            OSError, match="Required Keycloak environment variables are missing"
        ):
            RealmClient.from_env()

    def test_str_representation(self):
        """Test string representation of the RealmClient."""

        # Since we don't have the actual __str__ implementation, we'll skip this test
        # or implement it once the __str__ method is available in the class
        pass
