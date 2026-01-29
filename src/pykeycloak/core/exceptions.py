# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>


class KeycloakException(Exception):
    def __init__(
        self,
        message: str = "",
    ) -> None:
        self.message = message

    def __str__(self) -> str:
        return f"{self.message}"


class AccessTokenIsRequiredError(KeycloakException): ...


class KeycloakDecodingError(KeycloakException): ...


class KeycloakUnexpectedBehaviourException(KeycloakException):
    def __init__(
        self,
        message: str = "",
        description: str = "",
        affected_versions: list[str] | None = None,
    ) -> None:
        self.message = message
        self.description = description
        self.versions = affected_versions

    def __str__(self) -> str:
        return f"v:[{self.versions}]{self.message}: {self.description}"


class KeycloakHTTPException(KeycloakException):
    def __init__(
        self,
        message: str = "",
        status_code: int | None = None,
        content: bytes | None = None,
    ) -> None:
        Exception.__init__(self, message)

        self.status_code = status_code
        self.content = content
        self.message = message

    def __str__(self) -> str:
        if self.status_code is not None:
            return f"{self.status_code}: {self.message}"
        return f"{self.message}"


class KeycloakError(KeycloakHTTPException): ...


class KeycloakConflictError(KeycloakError): ...


class KeycloakNotFoundError(KeycloakError): ...


class KeycloakBadRequestError(KeycloakError): ...


class KeycloakUnprocessableEntityError(KeycloakError): ...


class KeycloakUnsupportedMediaTypeError(KeycloakError): ...


class KeycloakUnauthorisedError(KeycloakError): ...


class KeycloakForbiddenError(KeycloakError): ...


class KeycloakMethodNotAllowedError(KeycloakError): ...


class KeycloakServerError(KeycloakError): ...
