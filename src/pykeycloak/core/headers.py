from collections import deque
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from enum import StrEnum

from pykeycloak.core.sanitizer import SensitiveDataSanitizer


class ContentTypesEnums(StrEnum):
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    JSON = "application/json"


class HeaderKeys(StrEnum):
    CONTENT_TYPE = "Content-Type"
    AUTHORIZATION = "Authorization"


class Headers(Mapping[str, str]):
    def __init__(
        self,
        sanitizer: SensitiveDataSanitizer,
        headers: dict[str, str] | None = None,
        access_token: str | None = None,
    ) -> None:
        self.__headers: dict[str, str] = dict(headers) if headers else {}
        self.__stack: deque[dict[str, str]] = deque()
        self.__sanitizer: SensitiveDataSanitizer = sanitizer

        self.set_content_type_json()

        if access_token:
            self.set_authorization_bearer(access_token)

    @property
    def headers(self) -> dict[str, str]:
        return self.__headers.copy()

    def stash_headers_to_stack(self) -> None:
        self.__stack.append(self.headers)

    def restore_headers_from_stack(self) -> None:
        if not self.__stack:
            raise RuntimeError("No pushed header state to restore.")
        self.__headers = self.__stack.pop()

    @contextmanager
    def override_sync(self, temp_headers: dict[str, str]) -> Iterator["Headers"]:
        self.stash_headers_to_stack()
        try:
            self.__headers = temp_headers
            yield self
        finally:
            self.restore_headers_from_stack()

    def override_with_openid_headers(
        self, access_token: str | None = None
    ) -> AbstractContextManager["Headers"]:
        data = {"Content-Type": "application/x-www-form-urlencoded"}

        if access_token:
            data["Authorization"] = f"Bearer {access_token}"

        return self.override_sync(data)

    def set_authorization_bearer(self, token: str) -> None:
        self.__headers["Authorization"] = f"Bearer {token}"

    def set_content_type_json(self) -> None:
        self.__headers["Content-Type"] = "application/json"

    def set_content_type_urlencoded(self) -> None:
        self.__headers["Content-Type"] = ContentTypesEnums.FORM_URLENCODED

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self.__headers

    def __setitem__(self, key: str, value: str) -> None:
        self.__headers[key] = value

    def __getitem__(self, key: str) -> str:
        return self.__headers[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.__headers)

    def __len__(self) -> int:
        return len(self.__headers)

    def __repr__(self) -> str:
        headers = self.__sanitizer.sanitize(self.headers)

        return f"Headers({headers})"

    def __str__(self) -> str:
        headers = self.__sanitizer.sanitize(self.headers)

        if not isinstance(headers, dict):
            return ""

        return ", ".join(f"{key}: {value}" for key, value in headers.items())


def get_headers(
    access_token: str | None = None,
) -> Headers:
    return Headers(
        access_token=access_token,
        sanitizer=SensitiveDataSanitizer.from_env(),
    )
