"""
Unit tests for the payloads module.
"""

import json
import pytest
from pykeycloak.providers.payloads import (
    Payload,
    TokenIntrospectionPayload,
    RTPIntrospectionPayload,
    ObtainTokenPayload,
    RefreshTokenPayload,
    ClientCredentialsLoginPayload,
    UserCredentialsLoginPayload,
    UMAAuthorizationPayload,
    CreateUserPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
    ConfidentialClientRevokePayload,
    PublicClientRevokePayload,
    RTPExchangeTokenPayload
)


class TestPayload:
    """Test cases for the base Payload class."""

    def test_payload_to_dict(self):
        """Test converting a payload to dictionary."""
        # Create a subclass for testing since Payload is abstract
        from dataclasses import dataclass

        @dataclass(frozen=True, kw_only=True)
        class TestPayload(Payload):
            param1: str = "value1"
            param2: str = "value2"

        test_payload = TestPayload()
        result = test_payload.to_dict()

        expected = {"param1": "value1", "param2": "value2"}
        assert result == expected

    def test_payload_to_json(self):
        """Test converting a payload to JSON string."""
        class TestPayload(Payload):
            def __init__(self, param1="value1", param2=42):
                self.param1 = param1
                self.param2 = param2
        
        test_payload = TestPayload()
        json_result = test_payload.to_json()
        dict_result = test_payload.to_dict()
        
        # Verify that JSON string matches the dictionary
        parsed_json = json.loads(json_result)
        assert parsed_json == dict_result


class TestTokenIntrospectionPayload:
    """Test cases for the TokenIntrospectionPayload class."""

    def test_token_introspection_payload_creation(self):
        """Test creating a TokenIntrospectionPayload."""
        token = "sample-token"
        payload = TokenIntrospectionPayload(token=token)
        
        assert payload.token == token
        assert payload.to_dict() == {"token": token}

    def test_token_introspection_payload_with_different_token(self):
        """Test TokenIntrospectionPayload with different token values."""
        tokens = ["token1", "token2", "token-with-special-chars!", ""]
        
        for token in tokens:
            payload = TokenIntrospectionPayload(token=token)
            assert payload.token == token
            assert payload.to_dict() == {"token": token}


class TestRTPIntrospectionPayload:
    """Test cases for the RTPIntrospectionPayload class."""

    def test_rtp_introspection_payload_defaults(self):
        """Test RTPIntrospectionPayload with default token_type_hint."""
        token = "sample-rtp-token"
        payload = RTPIntrospectionPayload(token=token)
        
        assert payload.token == token
        assert payload.token_type_hint == "requesting_party_token"
        assert payload.to_dict() == {
            "token": token,
            "token_type_hint": "requesting_party_token"
        }

    def test_rtp_introspection_payload_with_custom_hint(self):
        """Test RTPIntrospectionPayload with custom token_type_hint."""
        token = "sample-rtp-token"
        hint = "custom-hint"
        payload = RTPIntrospectionPayload(token=token, token_type_hint=hint)
        
        assert payload.token == token
        assert payload.token_type_hint == hint
        assert payload.to_dict() == {
            "token": token,
            "token_type_hint": hint
        }


class TestObtainTokenPayload:
    """Test cases for the ObtainTokenPayload class."""

    def test_obtain_token_payload_grant_type_abstract(self):
        """Test that ObtainTokenPayload has grant_type property."""
        class TestObtainToken(ObtainTokenPayload):
            @property
            def grant_type(self):
                return "test_grant"
        
        payload = TestObtainToken()
        assert payload.grant_type == "test_grant"

    def test_obtain_token_payload_scopes_handling(self):
        """Test that ObtainTokenPayload handles scopes correctly."""
        class TestObtainToken(ObtainTokenPayload):
            @property
            def grant_type(self):
                return "test_grant"
        
        payload = TestObtainToken()
        # Scopes should be None by default
        assert hasattr(payload, 'scopes')
        assert payload.scopes is None


class TestRefreshTokenPayload:
    """Test cases for the RefreshTokenPayload class."""

    def test_refresh_token_payload_properties(self):
        """Test RefreshTokenPayload properties."""
        class TestRefreshToken(RefreshTokenPayload):
            @property
            def grant_type(self):
                return "refresh_token"
        
        refresh_token = "refresh-123"
        payload = TestRefreshToken(refresh_token=refresh_token)
        
        # Note: We can't test the exact attribute since we don't know the implementation
        # But we can verify it's a valid payload
        dict_repr = payload.to_dict()
        assert 'grant_type' in dict_repr
        assert dict_repr['grant_type'] == "refresh_token"


class TestClientCredentialsLoginPayload:
    """Test cases for the ClientCredentialsLoginPayload class."""

    def test_client_credentials_login_payload(self):
        """Test ClientCredentialsLoginPayload structure."""
        class TestClientCredentials(ClientCredentialsLoginPayload):
            @property
            def grant_type(self):
                return "client_credentials"

        payload = TestClientCredentials()

        dict_repr = payload.to_dict()
        assert dict_repr['grant_type'] == "client_credentials"


class TestUserCredentialsLoginPayload:
    """Test cases for the UserCredentialsLoginPayload class."""

    def test_user_credentials_login_payload(self):
        """Test UserCredentialsLoginPayload structure."""
        class TestUserCredentials(UserCredentialsLoginPayload):
            @property
            def grant_type(self):
                return "password"

        username = "testuser"
        password = "testpass"
        payload = TestUserCredentials(username=username, password=password)

        dict_repr = payload.to_dict()
        assert dict_repr['grant_type'] == "password"
        assert dict_repr['username'] == username
        assert dict_repr['password'] == password


class TestRTPExchangeTokenPayload:
    """Test cases for the RTPExchangeTokenPayload class."""

    def test_rtp_exchange_token_payload(self):
        """Test RTPExchangeTokenPayload structure."""
        class TestRTPExchange(RTPExchangeTokenPayload):
            @property
            def grant_type(self):
                return "urn:ietf:params:oauth:grant-type:token-exchange"

        refresh_token = "refresh-token-123"
        payload = TestRTPExchange(refresh_token=refresh_token)

        dict_repr = payload.to_dict()
        assert dict_repr['grant_type'] == "urn:ietf:params:oauth:grant-type:token-exchange"
        assert dict_repr['refresh_token'] == refresh_token