"""
Unit tests for the exceptions module.
"""

from pykeycloak.core.exceptions import (
    PyKeycloakAuthenticationError,
    PyKeycloakConnectionError,
    PyKeycloakDeprecationError,
    KeycloakException,
    PyKeycloakOperationError,
    PyKeycloakRPTNotFound,
    PyKeycloakSecretNotFound,
)


class TestPyKeycloakException:
    """Test cases for the base PyKeycloakException class."""

    def test_pykeycloak_exception_creation_with_message_only(self):
        """Test creating a PyKeycloakException with only a message."""
        message = "Test exception message"
        exception = KeycloakException(message)

        assert str(exception) == message
        assert exception.message == message
        assert exception.status_code is None
        assert exception.content is None

    def test_pykeycloak_exception_creation_with_status_code(self):
        """Test creating a PyKeycloakException with message and status code."""
        message = "Test exception message"
        status_code = 404
        exception = KeycloakException(message, status_code)

        assert str(exception) == f"{status_code}: {message}"
        assert exception.message == message
        assert exception.status_code == status_code
        assert exception.content is None

    def test_pykeycloak_exception_creation_with_content(self):
        """Test creating a PyKeycloakException with message and content."""
        message = "Test exception message"
        content = b"error content"
        status_code = 500
        exception = KeycloakException(message, status_code, content)

        assert str(exception) == f"{status_code}: {message}"
        assert exception.message == message
        assert exception.status_code == status_code
        assert exception.content == content

    def test_pykeycloak_exception_creation_with_none_values(self):
        """Test creating a PyKeycloakException with None values."""
        exception = KeycloakException()

        assert str(exception) == ""
        assert exception.message == ""
        assert exception.status_code is None
        assert exception.content is None

    def test_pykeycloak_exception_inheritance(self):
        """Test that PyKeycloakException inherits from Exception."""
        exception = KeycloakException("Test message")

        assert isinstance(exception, Exception)


class TestPyKeycloakSubExceptions:
    """Test cases for the PyKeycloakException subclasses."""

    def test_pykeycloak_authentication_error(self):
        """Test PyKeycloakAuthenticationError."""
        message = "Authentication failed"
        exception = PyKeycloakAuthenticationError(message)

        assert str(exception) == message
        assert isinstance(exception, KeycloakException)
        assert isinstance(exception, Exception)

    def test_pykeycloak_connection_error(self):
        """Test PyKeycloakConnectionError."""
        message = "Connection failed"
        status_code = 503
        exception = PyKeycloakConnectionError(message, status_code)

        assert str(exception) == f"{status_code}: {message}"
        assert isinstance(exception, KeycloakException)
        assert isinstance(exception, Exception)

    def test_pykeycloak_operation_error(self):
        """Test PyKeycloakOperationError."""
        message = "Operation failed"
        exception = PyKeycloakOperationError(message)

        assert str(exception) == message
        assert isinstance(exception, KeycloakException)
        assert isinstance(exception, Exception)

    def test_pykeycloak_deprecation_error(self):
        """Test PyKeycloakDeprecationError."""
        message = "Feature deprecated"
        exception = PyKeycloakDeprecationError(message)

        assert str(exception) == message
        assert isinstance(exception, KeycloakException)
        assert isinstance(exception, Exception)

    def test_pykeycloak_secret_not_found(self):
        """Test PyKeycloakSecretNotFound."""
        message = "Secret not found"
        exception = PyKeycloakSecretNotFound(message)

        assert str(exception) == message
        assert isinstance(exception, PyKeycloakOperationError)
        assert isinstance(exception, KeycloakException)
        assert isinstance(exception, Exception)

    def test_pykeycloak_rpt_not_found(self):
        """Test PyKeycloakRPTNotFound."""
        message = "RPT not found"
        exception = PyKeycloakRPTNotFound(message)

        assert str(exception) == message
        assert isinstance(exception, PyKeycloakOperationError)
        assert isinstance(exception, KeycloakException)
        assert isinstance(exception, Exception)

    def test_subclass_hierarchy(self):
        """Test the inheritance hierarchy of exception classes."""
        # PyKeycloakAuthenticationError, PyKeycloakConnectionError, PyKeycloakOperationError, PyKeycloakDeprecationError
        # all inherit directly from PyKeycloakException
        auth_error = PyKeycloakAuthenticationError()
        conn_error = PyKeycloakConnectionError()
        op_error = PyKeycloakOperationError()
        dep_error = PyKeycloakDeprecationError()

        assert isinstance(auth_error, KeycloakException)
        assert isinstance(conn_error, KeycloakException)
        assert isinstance(op_error, KeycloakException)
        assert isinstance(dep_error, KeycloakException)

        # PyKeycloakSecretNotFound and PyKeycloakRPTNotFound inherit from PyKeycloakOperationError
        secret_error = PyKeycloakSecretNotFound()
        rpt_error = PyKeycloakRPTNotFound()

        assert isinstance(secret_error, PyKeycloakOperationError)
        assert isinstance(rpt_error, PyKeycloakOperationError)
        assert isinstance(secret_error, KeycloakException)
        assert isinstance(rpt_error, KeycloakException)
