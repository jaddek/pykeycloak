"""
Unit tests for the sanitizer module.
"""

import pytest
from pykeycloak.core.sanitizer import SensitiveDataSanitizer
from collections.abc import Mapping, Sequence
from typing import Any


class TestSensitiveDataSanitizer:
    """Test cases for the SensitiveDataSanitizer class."""

    def test_default_sensitive_keys(self):
        """Test that the sanitizer has the correct default sensitive keys."""
        sanitizer = SensitiveDataSanitizer()
        
        expected_keys = {
            "client_secret",
            "refresh_token", 
            "access_token",
            "id_token",
            "password",
            "authorization"
        }
        
        assert sanitizer.sensitive_keys == expected_keys
        
        # Check that the lowercased version is also correct
        expected_lower_keys = {k.lower() for k in expected_keys}
        assert sanitizer._sensitive_keys_lower == expected_lower_keys

    def test_custom_sensitive_keys(self):
        """Test creating a sanitizer with custom sensitive keys."""
        custom_keys = frozenset({"custom_secret", "api_key", "token"})
        sanitizer = SensitiveDataSanitizer(sensitive_keys=custom_keys)

        assert sanitizer.sensitive_keys == custom_keys

        # Check that the lowercased version is also correct
        expected_lower_keys = {k.lower() for k in custom_keys}
        assert sanitizer._sensitive_keys_lower == expected_lower_keys

    def test_sanitize_simple_dict_with_sensitive_data(self):
        """Test sanitizing a simple dictionary with sensitive data."""
        sanitizer = SensitiveDataSanitizer()
        
        data = {
            "username": "john_doe",
            "password": "secret123",
            "email": "john@example.com"
        }
        
        expected = {
            "username": "john_doe",
            "password": "<hidden>",
            "email": "john@example.com"
        }
        
        result = sanitizer.sanitize(data)
        assert result == expected

    def test_sanitize_nested_dict_with_sensitive_data(self):
        """Test sanitizing a nested dictionary with sensitive data."""
        sanitizer = SensitiveDataSanitizer()
        
        data = {
            "user": {
                "username": "john_doe",
                "password": "secret123",
                "profile": {
                    "email": "john@example.com",
                    "access_token": "abc123xyz"
                }
            },
            "client_secret": "mysecret"
        }
        
        expected = {
            "user": {
                "username": "john_doe",
                "password": "<hidden>",
                "profile": {
                    "email": "john@example.com",
                    "access_token": "<hidden>"
                }
            },
            "client_secret": "<hidden>"
        }
        
        result = sanitizer.sanitize(data)
        assert result == expected

    def test_sanitize_list_containing_sensitive_data(self):
        """Test sanitizing a list containing dictionaries with sensitive data."""
        sanitizer = SensitiveDataSanitizer()
        
        data = [
            {
                "username": "john_doe",
                "password": "secret123"
            },
            {
                "username": "jane_doe",
                "access_token": "token123"
            }
        ]
        
        expected = [
            {
                "username": "john_doe",
                "password": "<hidden>"
            },
            {
                "username": "jane_doe",
                "access_token": "<hidden>"
            }
        ]
        
        result = sanitizer.sanitize(data)
        assert result == expected

    def test_sanitize_mixed_structure_with_sensitive_data(self):
        """Test sanitizing a complex mixed structure with sensitive data."""
        sanitizer = SensitiveDataSanitizer()
        
        data = {
            "users": [
                {
                    "id": 1,
                    "username": "john_doe",
                    "credentials": {
                        "password": "secret123",
                        "refresh_token": "refresh987"
                    }
                },
                {
                    "id": 2,
                    "username": "jane_doe",
                    "credentials": {
                        "password": "another_secret",
                        "id_token": "id456"
                    }
                }
            ],
            "config": {
                "client_secret": "very_secret",
                "public_setting": "not_secret"
            }
        }
        
        expected = {
            "users": [
                {
                    "id": 1,
                    "username": "john_doe",
                    "credentials": {
                        "password": "<hidden>",
                        "refresh_token": "<hidden>"
                    }
                },
                {
                    "id": 2,
                    "username": "jane_doe",
                    "credentials": {
                        "password": "<hidden>",
                        "id_token": "<hidden>"
                    }
                }
            ],
            "config": {
                "client_secret": "<hidden>",
                "public_setting": "not_secret"
            }
        }
        
        result = sanitizer.sanitize(data)
        assert result == expected

    def test_sanitize_case_insensitive_keys(self):
        """Test that sanitization is case-insensitive for keys."""
        sanitizer = SensitiveDataSanitizer()
        
        data = {
            "PASSWORD": "secret123",
            "Access_Token": "token123",
            "CLIENT_SECRET": "mysecret",
            "normal_field": "normal_value"
        }
        
        expected = {
            "PASSWORD": "<hidden>",
            "Access_Token": "<hidden>",
            "CLIENT_SECRET": "<hidden>",
            "normal_field": "normal_value"
        }
        
        result = sanitizer.sanitize(data)
        assert result == expected

    def test_sanitize_non_dict_or_list_data(self):
        """Test sanitizing non-dict/list data (should remain unchanged)."""
        sanitizer = SensitiveDataSanitizer()
        
        # Test with string
        result = sanitizer.sanitize("just a string")
        assert result == "just a string"
        
        # Test with integer
        result = sanitizer.sanitize(42)
        assert result == 42
        
        # Test with boolean
        result = sanitizer.sanitize(True)
        assert result is True
        
        # Test with None
        result = sanitizer.sanitize(None)
        assert result is None

    def test_sanitize_empty_dict_and_list(self):
        """Test sanitizing empty dict and list."""
        sanitizer = SensitiveDataSanitizer()
        
        # Test empty dict
        result = sanitizer.sanitize({})
        assert result == {}
        
        # Test empty list
        result = sanitizer.sanitize([])
        assert result == []

    def test_sanitize_numeric_and_boolean_values_in_sensitive_fields(self):
        """Test sanitizing fields with numeric and boolean values."""
        sanitizer = SensitiveDataSanitizer()
        
        data = {
            "password": 12345,  # Numeric password
            "access_token": True,  # Boolean token
            "refresh_token": False,  # Boolean refresh token
            "normal_field": "normal_value"
        }
        
        expected = {
            "password": "<hidden>",
            "access_token": "<hidden>",
            "refresh_token": "<hidden>",
            "normal_field": "normal_value"
        }
        
        result = sanitizer.sanitize(data)
        assert result == expected

    def test_sanitize_deeply_nested_structure(self):
        """Test sanitizing a deeply nested structure."""
        sanitizer = SensitiveDataSanitizer()
        
        data = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "password": "deep_secret",
                            "normal": "value"
                        }
                    }
                }
            }
        }
        
        expected = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "password": "<hidden>",
                            "normal": "value"
                        }
                    }
                }
            }
        }
        
        result = sanitizer.sanitize(data)
        assert result == expected