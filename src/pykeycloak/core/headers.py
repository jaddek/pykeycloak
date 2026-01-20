from enum import Enum


class ContentTypesEnums(str, Enum):
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    JSON = "application/json"


class HeaderKeys(str, Enum):
    CONTENT_TYPE = "Content-Type"
    AUTHORIZATION = "Authorization"


from typing import Self, Protocol


class HeadersProtocol(Protocol):
    def openid_bearer(self, bearer_token: str) -> dict[str, str]: ...
    def openid_basic(self, basic_token: str) -> dict[str, str]: ...
    def keycloak_bearer(self, bearer_token: str) -> dict[str, str]: ...

class HeaderFactory:
    __slots__ = ()

    def openid_basic(self, basic_token: str) -> dict[str, str]:
        return {
            HeaderKeys.AUTHORIZATION.value: f"Basic {basic_token}",
            HeaderKeys.CONTENT_TYPE.value: ContentTypesEnums.FORM_URLENCODED.value
        }

    def openid_bearer(self, bearer_token: str) -> dict[str, str]:
        return {
            HeaderKeys.AUTHORIZATION.value: f"Bearer {bearer_token}",
            HeaderKeys.CONTENT_TYPE.value: ContentTypesEnums.FORM_URLENCODED.value
        }

    def keycloak_bearer(self, bearer_token: str) -> dict[str, str]:
        return {
            HeaderKeys.AUTHORIZATION.value: f"Bearer {bearer_token}",
            HeaderKeys.CONTENT_TYPE.value: ContentTypesEnums.JSON.value
        }


class Headers:
    __slots__ = ("_data",)

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def bearer(self, token: str) -> Self:
        self._data[HeaderKeys.AUTHORIZATION.value] = f"Bearer {token}"
        return self

    def basic(self, b64_auth: str) -> Self:
        self._data[HeaderKeys.AUTHORIZATION.value] = f"Basic {b64_auth}"
        return self

    def json(self) -> Self:
        self._data["Content-Type"] = ContentTypesEnums.JSON.value
        return self

    def urlencoded(self) -> Self:
        self._data["Content-Type"] = ContentTypesEnums.FORM_URLENCODED.value
        return self

    def build(self) -> dict[str, str]:
        return self._data.copy()

    def __repr__(self) -> str:
        ct = self._data.get(HeaderKeys.CONTENT_TYPE.value, "none")
        auth = "<hidden>" if HeaderKeys.AUTHORIZATION.value in self._data else "none"
        return f"Headers(content_type={ct}, authorization={auth})"


def get_headers(
    access_token: str | None = None,
) -> Headers:
    return Headers(
    )
