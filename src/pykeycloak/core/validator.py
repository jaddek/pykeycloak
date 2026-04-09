from collections.abc import Callable
from functools import wraps
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from pykeycloak.core.response import KeycloakResponse, KeycloakResponseBuilder

from ..core.exceptions import (
    KeycloakBadRequestError,
    KeycloakConflictError,
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
from .protocols import KeycloakResponseProtocol, KeycloakResponseValidatorProtocol


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

    def validate(self, response: KeycloakResponseProtocol) -> None:
        if response.status_code not in self._SUCCESS_STATUSES:
            raise self._create_error(response)

    def _create_error(self, response: KeycloakResponseProtocol) -> KeycloakException:
        status = response.status_code
        error = self._EXCEPTION_MAP.get(status, KeycloakServerError)

        error_detail = response.text or "No detail provided"
        return error(
            message=f"Keycloak {status}: {error_detail}",
            status_code=status,
            content=response.content,
        )


_builder = KeycloakResponseBuilder()


def validate_api_response(method: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(method)
    async def wrapper(self: Any, *args: Any, **kwargs: Any) -> KeycloakResponse:
        response = await method(self, *args, **kwargs)
        self._validator.validate(response)
        return _builder.build_response(response)

    return wrapper


if TYPE_CHECKING:
    _: KeycloakResponseValidatorProtocol = type[KeycloakResponseValidator]
