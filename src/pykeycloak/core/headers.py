from enum import StrEnum


class ContentTypesEnums(StrEnum):
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    JSON = "application/json"


class HeaderKeys(StrEnum):
    CONTENT_TYPE = "Content-Type"
    AUTHORIZATION = "Authorization"


from typing import Self, Protocol


class SupportsAuthHeaders(Protocol):
    def openid_bearer(self, bearer_token: str) -> dict[str, str]: ...
    def openid_basic(self, b64_auth: str) -> dict[str, str]: ...

class HeaderFactory:
    __slots__ = ()  # Класс вообще не хранит данных

    @staticmethod
    def openid_basic(basic_token: str) -> dict[str, str]:
        return {
            "Authorization": f"Basic {basic_token}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

    @staticmethod
    def openid_bearer(bearer_token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

    @staticmethod
    def keycloak_bearer(bearer_token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json"
        }



class Headers:
    __slots__ = ("_data",)

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def bearer(self, token: str) -> Self:
        self._data["Authorization"] = f"Bearer {token}"
        return self

    def basic(self, b64_auth: str) -> Self:
        self._data["Authorization"] = f"Basic {b64_auth}"
        return self

    def json(self) -> Self:
        self._data["Content-Type"] = "application/json"
        return self

    def urlencoded(self) -> Self:
        self._data["Content-Type"] = "application/x-www-form-urlencoded"
        return self

    def build(self) -> dict[str, str]:
        return self._data.copy()

    def __repr__(self) -> str:
        ct = self._data.get("Content-Type", "none")
        auth = "<hidden>" if "Authorization" in self._data else "none"
        return f"Headers(content_type={ct}, authorization={auth})"


def get_headers(
    access_token: str | None = None,
) -> Headers:
    return Headers(
    )
