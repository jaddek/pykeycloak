"""
Unit tests for the clients module.
"""

import pytest
from pykeycloak.core.clients import HttpMethod


class TestHttpMethod:
    """Test cases for the HttpMethod enum."""

    def test_http_method_values(self):
        """Test that HttpMethod enum has correct values."""
        assert HttpMethod.GET.value == "GET"
        assert HttpMethod.POST.value == "POST"
        assert HttpMethod.PUT.value == "PUT"
        assert HttpMethod.DELETE.value == "DELETE"
        assert HttpMethod.PATCH.value == "PATCH"
        assert HttpMethod.HEAD.value == "HEAD"
        assert HttpMethod.OPTIONS.value == "OPTIONS"

    def test_all_http_methods_exist(self):
        """Test that all expected HTTP methods are present."""
        expected_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        actual_methods = {method.value for method in HttpMethod}
        
        assert actual_methods == expected_methods

    def test_http_method_can_be_used_as_string(self):
        """Test that HttpMethod values can be used as strings."""
        method = HttpMethod.GET
        assert str(method.value) == "GET"
        assert method.value == "GET"

        # Test comparison with string
        assert method == HttpMethod.GET
        assert method.value == "GET"