"""
Unit tests for the helpers module.
"""

import os
from unittest.mock import patch

import pytest

from pykeycloak.core.helpers import (
    getenv_bool,
    getenv_int,
    getenv_optional,
    getenv_required,
    getenv_required_url,
)


class TestGetEnvRequiredUrl:
    """Test cases for the getenv_required_url function."""

    def test_getenv_required_url_with_valid_url(self):
        """Test getting a required URL from environment variables."""
        with patch.dict(os.environ, {"TEST_URL": "https://example.com"}):
            result = getenv_required_url("TEST_URL")
            assert result == "https://example.com"

    def test_getenv_required_url_with_invalid_url_missing_scheme(self):
        """Test that an invalid URL without scheme raises RuntimeError."""
        with patch.dict(os.environ, {"TEST_URL": "example.com"}):
            with pytest.raises(RuntimeError, match="must be a valid URL"):
                getenv_required_url("TEST_URL")

    def test_getenv_required_url_with_invalid_url_missing_netloc(self):
        """Test that an invalid URL without netloc raises RuntimeError."""
        with patch.dict(os.environ, {"TEST_URL": "https:"}):
            with pytest.raises(RuntimeError, match="must be a valid URL"):
                getenv_required_url("TEST_URL")

    def test_getenv_required_url_with_empty_string(self):
        """Test that an empty string raises RuntimeError."""
        with patch.dict(os.environ, {"TEST_URL": ""}):
            with pytest.raises(RuntimeError, match="is not set"):
                getenv_required_url("TEST_URL")

    def test_getenv_required_url_with_nonexistent_variable(self):
        """Test that a nonexistent environment variable raises RuntimeError."""
        # Remove the variable if it exists
        if "NONEXISTENT_VAR" in os.environ:
            del os.environ["NONEXISTENT_VAR"]

        with pytest.raises(
            RuntimeError,
            match="Required environment variable 'NONEXISTENT_VAR' is not set",
        ):
            getenv_required_url("NONEXISTENT_VAR")


class TestGetEnvRequired:
    """Test cases for the getenv_required function."""

    def test_getenv_required_with_existing_variable(self):
        """Test getting a required environment variable that exists."""
        with patch.dict(os.environ, {"TEST_VAR": "test_value"}):
            result = getenv_required("TEST_VAR")
            assert result == "test_value"

    def test_getenv_required_with_nonexistent_variable(self):
        """Test that a nonexistent environment variable raises RuntimeError."""
        # Remove the variable if it exists
        if "NONEXISTENT_VAR" in os.environ:
            del os.environ["NONEXISTENT_VAR"]

        with pytest.raises(
            RuntimeError,
            match="Required environment variable 'NONEXISTENT_VAR' is not set",
        ):
            getenv_required("NONEXISTENT_VAR")

    def test_getenv_required_with_empty_string(self):
        """Test getting a required environment variable with empty string value."""
        with patch.dict(os.environ, {"TEST_VAR": ""}):
            with pytest.raises(RuntimeError, match="is not set"):
                getenv_required("TEST_VAR")


class TestGetEnvOptional:
    """Test cases for the getenv_optional function."""

    def test_getenv_optional_with_existing_variable(self):
        """Test getting an optional environment variable that exists."""
        with patch.dict(os.environ, {"TEST_VAR": "test_value"}):
            result = getenv_optional("TEST_VAR")
            assert result == "test_value"

    def test_getenv_optional_with_empty_string(self):
        """Test getting an optional environment variable with empty string value."""
        with patch.dict(os.environ, {"TEST_VAR": ""}):
            result = getenv_optional("TEST_VAR")
            assert result is None

    def test_getenv_optional_with_none_value(self):
        """Test getting an optional environment variable that doesn't exist."""
        # Remove the variable if it exists
        if "NONEXISTENT_VAR" in os.environ:
            del os.environ["NONEXISTENT_VAR"]

        result = getenv_optional("NONEXISTENT_VAR")
        assert result is None

    def test_getenv_optional_with_whitespace_string(self):
        """Test getting an optional environment variable with whitespace string."""
        with patch.dict(os.environ, {"TEST_VAR": "   "}):
            result = getenv_optional("TEST_VAR")
            assert result == "   "


class TestGetEnvBool:
    """Test cases for the getenv_bool function."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("1", True),
            ("true", True),
            ("True", True),
            ("TRUE", True),
            ("yes", True),
            ("Yes", True),
            ("YES", True),
            ("on", True),
            ("On", True),
            ("ON", True),
            ("0", False),
            ("false", False),
            ("False", False),
            ("FALSE", False),
            ("no", False),
            ("No", False),
            ("NO", False),
            ("off", False),
            ("Off", False),
            ("OFF", False),
            ("invalid", False),
        ],
    )
    def test_getenv_bool_variations(self, value, expected):
        """Test various string values for boolean conversion."""
        with patch.dict(os.environ, {"TEST_BOOL": value}):
            result = getenv_bool("TEST_BOOL", False)
            assert result == expected

    def test_getenv_bool_with_unset_variable(self):
        """Test getenv_bool with an unset environment variable."""
        # Remove the variable if it exists
        if "NONEXISTENT_VAR" in os.environ:
            del os.environ["NONEXISTENT_VAR"]

        result = getenv_bool("NONEXISTENT_VAR", True)
        assert result is True  # Should return the default value

    def test_getenv_bool_with_empty_string(self):
        """Test getenv_bool with an empty string value."""
        with patch.dict(os.environ, {"TEST_BOOL": ""}):
            result = getenv_bool("TEST_BOOL", True)
            assert result is False  # Empty string should return False, not the default


class TestGetEnvInt:
    """Test cases for the getenv_int function."""

    def test_getenv_int_with_valid_integer(self):
        """Test getting an integer from environment variable."""
        with patch.dict(os.environ, {"TEST_INT": "42"}):
            result = getenv_int("TEST_INT", 0)
            assert result == 42

    def test_getenv_int_with_invalid_string(self):
        """Test getting an integer from environment variable with invalid string."""
        with patch.dict(os.environ, {"TEST_INT": "not_an_int"}):
            result = getenv_int("TEST_INT", 42)
            assert result == 42  # Should return the default value

    def test_getenv_int_with_unset_variable(self):
        """Test getenv_int with an unset environment variable."""
        # Remove the variable if it exists
        if "NONEXISTENT_VAR" in os.environ:
            del os.environ["NONEXISTENT_VAR"]

        result = getenv_int("NONEXISTENT_VAR", 123)
        assert result == 123  # Should return the default value

    def test_getenv_int_with_negative_number(self):
        """Test getting a negative integer from environment variable."""
        with patch.dict(os.environ, {"TEST_INT": "-5"}):
            result = getenv_int("TEST_INT", 0)
            assert result == -5

    def test_getenv_int_with_zero(self):
        """Test getting zero from environment variable."""
        with patch.dict(os.environ, {"TEST_INT": "0"}):
            result = getenv_int("TEST_INT", 100)
            assert result == 0

    def test_getenv_int_with_large_number(self):
        """Test getting a large integer from environment variable."""
        large_num = "999999999"
        with patch.dict(os.environ, {"TEST_INT": large_num}):
            result = getenv_int("TEST_INT", 0)
            assert result == int(large_num)
