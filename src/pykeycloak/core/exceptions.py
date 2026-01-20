class PyKeycloakException(Exception):
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


class PyKeycloakAuthenticationError(PyKeycloakException):
    ...


class PyKeycloakConnectionError(PyKeycloakException):
    ...


class PyKeycloakOperationError(PyKeycloakException):
    ...


class PyKeycloakDeprecationError(PyKeycloakException):
    ...


class PyKeycloakSecretNotFound(PyKeycloakOperationError):
    ...


class PyKeycloakRPTNotFound(PyKeycloakOperationError):
    ...


class PyKeycloakAuthorizationConfigError(PyKeycloakOperationError):
    ...


class PyKeycloakInvalidTokenError(PyKeycloakOperationError):
    ...
