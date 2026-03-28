# SPDX-License-Identifier: MIT
import pytest

from pykeycloak.core.exceptions import (
    AccessTokenIsRequiredError,
    KeycloakBadRequestError,
    KeycloakConflictError,
    KeycloakDecodingError,
    KeycloakError,
    KeycloakException,
    KeycloakForbiddenError,
    KeycloakHTTPException,
    KeycloakMethodNotAllowedError,
    KeycloakNotFoundError,
    KeycloakServerError,
    KeycloakUnauthorisedError,
    KeycloakUnexpectedBehaviourException,
    KeycloakUnprocessableEntityError,
    KeycloakUnsupportedMediaTypeError,
)


class TestKeycloakException:
    def test_str_with_message(self):
        exc = KeycloakException(message="something went wrong")
        assert str(exc) == "something went wrong"

    def test_str_with_empty_message(self):
        exc = KeycloakException()
        assert str(exc) == ""

    def test_is_exception(self):
        assert isinstance(KeycloakException(), Exception)


class TestKeycloakUnexpectedBehaviourException:
    def test_str_includes_versions_and_message(self):
        exc = KeycloakUnexpectedBehaviourException(
            message="bug",
            description="details here",
            affected_versions=["26.3.3"],
        )
        result = str(exc)
        assert "26.3.3" in result
        assert "bug" in result
        assert "details here" in result

    def test_attributes_stored(self):
        exc = KeycloakUnexpectedBehaviourException(
            message="m", description="d", affected_versions=["1.0"]
        )
        assert exc.message == "m"
        assert exc.description == "d"
        assert exc.versions == ["1.0"]


class TestKeycloakHTTPException:
    def test_str_with_status_code(self):
        exc = KeycloakHTTPException(message="not found", status_code=404)
        assert str(exc) == "404: not found"

    def test_str_without_status_code(self):
        exc = KeycloakHTTPException(message="error")
        assert str(exc) == "error"

    def test_attributes(self):
        content = b"error body"
        exc = KeycloakHTTPException(message="msg", status_code=500, content=content)
        assert exc.status_code == 500
        assert exc.content == content
        assert exc.message == "msg"


class TestExceptionHierarchy:
    def test_all_errors_inherit_from_keycloak_error(self):
        for cls in [
            KeycloakNotFoundError,
            KeycloakConflictError,
            KeycloakBadRequestError,
            KeycloakUnauthorisedError,
            KeycloakForbiddenError,
            KeycloakUnprocessableEntityError,
            KeycloakUnsupportedMediaTypeError,
            KeycloakMethodNotAllowedError,
            KeycloakServerError,
        ]:
            assert issubclass(cls, KeycloakError)

    def test_keycloak_error_inherits_http_exception(self):
        assert issubclass(KeycloakError, KeycloakHTTPException)

    def test_keycloak_http_exception_inherits_keycloak_exception(self):
        assert issubclass(KeycloakHTTPException, KeycloakException)

    def test_access_token_error_inherits_keycloak_exception(self):
        assert issubclass(AccessTokenIsRequiredError, KeycloakException)

    def test_decoding_error_inherits_keycloak_exception(self):
        assert issubclass(KeycloakDecodingError, KeycloakException)

    def test_can_catch_all_as_keycloak_exception(self):
        with pytest.raises(KeycloakException):
            raise KeycloakNotFoundError(message="not found", status_code=404)
