"""
Unit tests for the services module.
"""

from unittest.mock import Mock

import pytest
from httpx import Response

from pykeycloak.services.services import BaseService


class TestBaseService:
    """Test cases for the BaseService class."""

    def test_base_service_initialization(self):
        """Test initializing a BaseService with a provider."""
        mock_provider = Mock()
        service = BaseService(mock_provider)

        assert service._provider == mock_provider

    def test_validate_response_success(self):
        """Test validate_response with a successful response."""
        # Create a mock response with JSON data
        mock_response = Mock(spec=Response)
        mock_response.json.return_value = {"key": "value", "list": [1, 2, 3]}

        result = BaseService.validate_response(mock_response)

        assert result == {"key": "value", "list": [1, 2, 3]}
        mock_response.json.assert_called_once()

    def test_validate_response_with_list(self):
        """Test validate_response with a list response."""
        # Create a mock response with JSON list
        mock_response = Mock(spec=Response)
        mock_response.json.return_value = [1, 2, 3, {"nested": "value"}]

        result = BaseService.validate_response(mock_response)

        assert result == [1, 2, 3, {"nested": "value"}]

    def test_validate_response_with_non_json_content(self):
        """Test validate_response when response is not JSON decodable."""
        # Create a mock response that raises an exception when json() is called
        mock_response = Mock(spec=Response)
        mock_response.json.side_effect = Exception("Invalid JSON")

        with pytest.raises(ValueError, match="Failed to decode JSON response"):
            BaseService.validate_response(mock_response)

    def test_validate_response_with_non_dict_or_list_json(self):
        """Test validate_response when JSON is neither dict nor list."""
        # Create a mock response with a string instead of dict/list
        mock_response = Mock(spec=Response)
        mock_response.json.return_value = "just a string"

        with pytest.raises(TypeError, match="Expected JSON dict or list, got str"):
            BaseService.validate_response(mock_response)

    def test_validate_response_with_number_json(self):
        """Test validate_response when JSON is a number."""
        # Create a mock response with a number instead of dict/list
        mock_response = Mock(spec=Response)
        mock_response.json.return_value = 42

        with pytest.raises(TypeError, match="Expected JSON dict or list, got int"):
            BaseService.validate_response(mock_response)

    def test_validate_response_with_boolean_json(self):
        """Test validate_response when JSON is a boolean."""
        # Create a mock response with a boolean instead of dict/list
        mock_response = Mock(spec=Response)
        mock_response.json.return_value = True

        with pytest.raises(TypeError, match="Expected JSON dict or list, got bool"):
            BaseService.validate_response(mock_response)

    def test_validate_response_with_null_json(self):
        """Test validate_response when JSON is null."""
        # Create a mock response with null instead of dict/list
        mock_response = Mock(spec=Response)
        mock_response.json.return_value = None

        with pytest.raises(TypeError, match="Expected JSON dict or list, got NoneType"):
            BaseService.validate_response(mock_response)
