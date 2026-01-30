import json
from collections.abc import Callable
from functools import wraps
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, cast

from pykeycloak.core.types import JsonData

from ..core.exceptions import (
    KeycloakBadRequestError,
    KeycloakConflictError,
    KeycloakDecodingError,
    KeycloakError,
    KeycloakException,
    KeycloakForbiddenError,
    KeycloakMethodNotAllowedError,
    KeycloakNotFoundError,
    KeycloakServerError,
    KeycloakUnauthorisedError,
    KeycloakUnprocessableEntityError,
)
from .exceptions import KeycloakUnsupportedMediaTypeError
from .protocols import KeycloakResponseValidatorProtocol, ResponseProtocol


class KeycloakResponseValidator:
    _EXCEPTION_MAP: dict[int, type[KeycloakError]] = {
        HTTPStatus.NOT_FOUND: KeycloakNotFoundError,
        HTTPStatus.CONFLICT: KeycloakConflictError,
        HTTPStatus.BAD_REQUEST: KeycloakBadRequestError,
        HTTPStatus.UNAUTHORIZED: KeycloakUnauthorisedError,
        HTTPStatus.FORBIDDEN: KeycloakForbiddenError,
        HTTPStatus.UNPROCESSABLE_ENTITY: KeycloakUnprocessableEntityError,
        HTTPStatus.METHOD_NOT_ALLOWED: KeycloakMethodNotAllowedError,
        HTTPStatus.UNSUPPORTED_MEDIA_TYPE: KeycloakUnsupportedMediaTypeError,
    }

    _SUCCESS_STATUSES = {HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.NO_CONTENT}

    _NO_BODY_STATUSES = {HTTPStatus.CREATED, HTTPStatus.NO_CONTENT}

    def validate(self, response: ResponseProtocol) -> JsonData:
        if response.status_code in self._SUCCESS_STATUSES:
            return self._parse_json(response)

        raise self._create_error(response)

    def _create_error(self, response: ResponseProtocol) -> KeycloakException:
        status = response.status_code
        error = self._EXCEPTION_MAP.get(status, KeycloakServerError)

        error_detail = response.text or "No detail provided"
        return error(
            message=f"Keycloak {status}: {error_detail}",
            status_code=status,
            content=response.content,
        )

    def _parse_json(self, response: ResponseProtocol) -> JsonData:
        if response.status_code in self._NO_BODY_STATUSES or not response.text.strip():
            return None

        try:
            return response.json()
        except (json.JSONDecodeError, ValueError) as e:
            raise KeycloakDecodingError(
                f"Malformed JSON: {str(e)} | Content: {response.text[:100]}"
            ) from e


def validate_api_response(method: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(method)
    async def wrapper(self: Any, *args: Any, **kwargs: Any) -> JsonData:
        response = await method(self, *args, **kwargs)
        return cast(JsonData, self._validator.validate(response))

    return wrapper


if TYPE_CHECKING:
    _: KeycloakResponseValidatorProtocol = type[KeycloakResponseValidator]
