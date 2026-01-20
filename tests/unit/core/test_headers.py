"""
Unit tests for the headers module.
"""

from pykeycloak.core.headers import ContentTypesEnums, HeaderFactory, HeaderKeys


class TestContentTypesEnums:
    """Test cases for the ContentTypesEnums class."""

    def test_form_urlencoded_value(self):
        """Test the value of FORM_URLENCODED enum member."""
        assert (
            ContentTypesEnums.FORM_URLENCODED.value
            == "application/x-www-form-urlencoded"
        )

    def test_json_value(self):
        """Test the value of JSON enum member."""
        assert ContentTypesEnums.JSON.value == "application/json"

    def test_all_content_type_values(self):
        """Test that all ContentTypesEnums members have correct values."""
        expected_values = ["application/x-www-form-urlencoded", "application/json"]
        actual_values = [content_type.value for content_type in ContentTypesEnums]
        assert sorted(actual_values) == sorted(expected_values)


class TestHeaderKeys:
    """Test cases for the HeaderKeys class."""

    def test_content_type_value(self):
        """Test the value of CONTENT_TYPE header key."""
        assert HeaderKeys.CONTENT_TYPE.value == "Content-Type"

    def test_authorization_value(self):
        """Test the value of AUTHORIZATION header key."""
        assert HeaderKeys.AUTHORIZATION.value == "Authorization"

    def test_all_header_keys_values(self):
        """Test that all HeaderKeys members have correct values."""
        expected_values = ["Content-Type", "Authorization"]
        actual_values = [header_key.value for header_key in HeaderKeys]
        assert sorted(actual_values) == sorted(expected_values)


class TestHeaderFactory:
    """Test cases for the HeaderFactory class."""

    def test_openid_basic_headers(self):
        """Test creating basic auth headers for OpenID."""
        basic_token = "dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ="  # noqa: S106 S105
        expected_headers = {
            "Authorization": f"Basic {basic_token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        factory = HeaderFactory()
        result = factory.openid_basic(basic_token)
        assert result == expected_headers

    def test_openid_bearer_headers(self):
        """Test creating bearer token headers for OpenID."""
        bearer_token = "sample-bearer-token"  # noqa: S106 S105
        expected_headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        factory = HeaderFactory()
        result = factory.openid_bearer(bearer_token)
        assert result == expected_headers

    def test_keycloak_bearer_headers(self):
        """Test creating bearer token headers for Keycloak."""
        bearer_token = "sample-keycloak-token"  # noqa: S106 S105
        expected_headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        }

        factory = HeaderFactory()
        result = factory.keycloak_bearer(bearer_token)
        assert result == expected_headers

    def test_different_bearer_tokens_produce_different_headers(self):
        """Test that different bearer tokens produce appropriately different headers."""
        token1 = "first-token"
        token2 = "second-token"

        factory = HeaderFactory()
        headers1 = factory.openid_bearer(token1)
        headers2 = factory.openid_bearer(token2)

        assert headers1 != headers2
        assert headers1["Authorization"] == f"Bearer {token1}"
        assert headers2["Authorization"] == f"Bearer {token2}"

    def test_different_basic_tokens_produce_different_headers(self):
        """Test that different basic tokens produce appropriately different headers."""
        token1 = "first-basic-token"
        token2 = "second-basic-token"

        factory = HeaderFactory()
        headers1 = factory.openid_basic(token1)
        headers2 = factory.openid_basic(token2)

        assert headers1 != headers2
        assert headers1["Authorization"] == f"Basic {token1}"
        assert headers2["Authorization"] == f"Basic {token2}"

    def test_headers_immutability(self):
        """Test that returned headers dictionaries are independent."""
        basic_token = "test-token"  # noqa: S106 S105
        factory = HeaderFactory()
        headers1 = factory.openid_basic(basic_token)
        headers2 = factory.openid_basic(basic_token)

        # Modify one of the headers
        headers1["Custom-Header"] = "custom-value"

        # The other should remain unchanged
        assert "Custom-Header" not in headers2
        assert headers1 != headers2

    def test_headers_content_type_consistency(self):
        """Test that OpenID headers consistently include form urlencoded content type."""
        token = "any-token"  # noqa: S106 S105

        factory = HeaderFactory()
        basic_headers = factory.openid_basic(token)
        bearer_headers = factory.openid_bearer(token)

        assert basic_headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert bearer_headers["Content-Type"] == "application/x-www-form-urlencoded"

    def test_factory_class_has_no_instance_data(self):
        """Test that HeaderFactory class doesn't store any instance data."""
        factory1 = HeaderFactory()
        factory2 = HeaderFactory()

        # Both instances should behave identically
        token = "test-token"  # noqa: S106 S105
        headers1 = factory1.openid_bearer(token)
        headers2 = factory2.openid_bearer(token)

        assert headers1 == headers2
