# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import json
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any

from httpx import Headers

from pykeycloak.core.exceptions import KeycloakDecodingError
from pykeycloak.core.types import JsonData


@dataclass(frozen=True, slots=True)
class KeycloakResponse:
    status_code: int
    headers: Headers
    body: JsonData
    text: str
    content: bytes

    @property
    def status(self) -> HTTPStatus:
        return HTTPStatus(self.status_code)

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    def header(self, key: str, default: str | None = None) -> Any:
        return self.headers.get(key, default)

    def __getitem__(self, key: str) -> Any:
        if not isinstance(self.body, dict):
            raise TypeError("body is not a mapping")
        return self.body[key]

    def get(self, key: str, default: Any = None) -> Any:
        if not isinstance(self.body, dict):
            return default
        return self.body.get(key, default)


class KeycloakResponseBuilder:
    _NO_BODY_STATUSES = {HTTPStatus.CREATED, HTTPStatus.NO_CONTENT}

    def build_response(self, response: Any) -> "KeycloakResponse":
        if response.status_code in self._NO_BODY_STATUSES or not response.text.strip():
            body: JsonData = None
        else:
            try:
                body = response.json()
            except (json.JSONDecodeError, ValueError) as e:
                raise KeycloakDecodingError(
                    f"Malformed JSON: {str(e)} | Content: {response.text[:100]}"
                ) from e

        return KeycloakResponse(
            status_code=response.status_code,
            headers=response.headers,
            body=body,
            text=response.text,
            content=response.content,
        )
