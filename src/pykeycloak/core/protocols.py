from typing import Any, Protocol

from httpx._types import HeaderTypes

from pykeycloak.core.types import JsonData


class ResponseProtocol(Protocol):
    status_code: int
    headers: HeaderTypes | None = (None,)

    @property
    def text(self) -> str: ...

    @property
    def content(self) -> bytes: ...

    def json(self, **kwargs: Any) -> JsonData: ...


class KeycloakResponseValidatorProtocol(Protocol):
    def validate(self, /, response: ResponseProtocol) -> JsonData: ...
