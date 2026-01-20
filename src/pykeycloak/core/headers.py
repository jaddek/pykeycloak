# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from enum import Enum


class ContentTypesEnums(str, Enum):
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    JSON = "application/json"


class HeaderKeys(str, Enum):
    CONTENT_TYPE = "Content-Type"
    AUTHORIZATION = "Authorization"


from typing import Protocol


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