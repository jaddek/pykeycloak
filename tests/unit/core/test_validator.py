# SPDX-License-Identifier: MIT
import pytest

from pykeycloak.core.exceptions import (
    KeycloakBadRequestError,
    KeycloakConflictError,
    KeycloakDecodingError,
    KeycloakForbiddenError,
    KeycloakMethodNotAllowedError,
    KeycloakNotFoundError,
    KeycloakServerError,
    KeycloakUnauthorisedError,
    KeycloakUnprocessableEntityError,
    KeycloakUnsupportedMediaTypeError,
)
from pykeycloak.core.validator import KeycloakResponseValidator


def make_response(status_code, text="", content=b"", json_data=None):
    from unittest.mock import MagicMock

    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = content
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("No JSON")
    return resp


@pytest.fixture
def validator():
    return KeycloakResponseValidator()


class TestValidateSuccess:
    def test_200_returns_json(self, validator):
        resp = make_response(200, text='{"key": "val"}', json_data={"key": "val"})
        result = validator.validate(resp)
        assert result == {"key": "val"}

    def test_201_returns_none(self, validator):
        resp = make_response(201, text="")
        result = validator.validate(resp)
        assert result is None

    def test_204_returns_none(self, validator):
        resp = make_response(204, text="")
        result = validator.validate(resp)
        assert result is None

    def test_200_empty_body_returns_none(self, validator):
        resp = make_response(200, text="   ")
        result = validator.validate(resp)
        assert result is None

    def test_200_malformed_json_raises_decoding_error(self, validator):
        resp = make_response(200, text="not json")
        resp.json.side_effect = ValueError("bad json")
        with pytest.raises(KeycloakDecodingError):
            validator.validate(resp)


class TestValidateErrors:
    @pytest.mark.parametrize(
        "status_code, exc_cls",
        [
            (404, KeycloakNotFoundError),
            (409, KeycloakConflictError),
            (400, KeycloakBadRequestError),
            (401, KeycloakUnauthorisedError),
            (403, KeycloakForbiddenError),
            (422, KeycloakUnprocessableEntityError),
            (405, KeycloakMethodNotAllowedError),
            (415, KeycloakUnsupportedMediaTypeError),
            (500, KeycloakServerError),
            (503, KeycloakServerError),
        ],
    )
    def test_raises_correct_exception(self, validator, status_code, exc_cls):
        resp = make_response(status_code, text="error detail", content=b"error detail")
        with pytest.raises(exc_cls):
            validator.validate(resp)

    def test_exception_contains_status_code(self, validator):
        resp = make_response(404, text="not found", content=b"not found")
        with pytest.raises(KeycloakNotFoundError) as exc_info:
            validator.validate(resp)
        assert exc_info.value.status_code == 404

    def test_exception_contains_content(self, validator):
        resp = make_response(409, text="conflict", content=b"conflict")
        with pytest.raises(KeycloakConflictError) as exc_info:
            validator.validate(resp)
        assert exc_info.value.content == b"conflict"
