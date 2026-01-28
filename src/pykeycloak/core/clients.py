# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>
from enum import Enum
from types import TracebackType
from typing import Any

from httpx import (
    AsyncClient,
    AsyncHTTPTransport,
    HTTPStatusError,
    RequestError,
    Response,
)

from .. import logger
from .settings import ClientSettings, HttpTransportSettings


class HttpMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class KeycloakHttpClientWrapperSync: ...


class KeycloakHttpClientWrapperAsync:
    def __init__(
        self,
        client_settings: ClientSettings | None = None,
        transport_settings: HttpTransportSettings | None = None,
    ):
        transport_settings = transport_settings or HttpTransportSettings()
        transport = AsyncHTTPTransport(**transport_settings.to_dict())

        client_settings = client_settings or ClientSettings()
        client_settings.transport = transport

        self._client = AsyncClient(**client_settings.to_dict())

    @property
    def client(self) -> AsyncClient:
        return self._client

    @staticmethod
    def init_default_client() -> "KeycloakHttpClientWrapperAsync":
        return KeycloakHttpClientWrapperAsync()

    def log_client_config_before_request(self) -> None:
        # Достаем настройки пула безопасно
        pool = getattr(self.client._transport, "_pool", None)

        max_conns = getattr(pool, "_max_connections", "N/A")
        max_keepalive = getattr(pool, "_max_keepalive_connections", "N/A")
        keepalive_expiry = getattr(pool, "_keepalive_expiry", "N/A")

        logger.debug(
            "HTTPX\n=========================================\n"
            " HTTPX Client Configuration:\n"
            " timeouts=%s, max_connections=%s, max_keepalive=%s, keepalive_expiry=%s,\n"
            " base_url=%s, default_headers=%s\n"
            "=========================================",
            self.client.timeout,
            max_conns,
            max_keepalive,
            keepalive_expiry,
            self.client.base_url,
            self.client.headers,
        )

    async def request(
        self, method: HttpMethod, url: str, raise_exception: bool = False, **kwargs: Any
    ) -> Response:
        try:
            logger.debug("Request method: %s, url: %s kwargs %s", method, url, kwargs)
            self.log_client_config_before_request()

            response = await self.client.request(method=method.value, url=url, **kwargs)

            logger.debug(
                "Response method: %s:%s, url: %s, content: %s, headers: %s",
                method,
                response.status_code,
                url,
                response.text,
                response.headers,
            )

            if raise_exception:
                response.raise_for_status()

            return response
        except RequestError as e:
            logger.error(f"Error: {e}")
            raise
        except HTTPStatusError as e:
            logger.error(f"Error: {e}")
            raise

    async def __aenter__(self) -> "KeycloakHttpClientWrapperAsync":
        await self._client.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        await self._client.__aexit__(exc_type, exc_value, traceback)

    async def close(self) -> None:
        await self._client.aclose()


def get_keycloak_client_wrapper_from_env() -> KeycloakHttpClientWrapperAsync:
    return get_keycloak_client_wrapper(
        client_settings=ClientSettings.from_env(),
        transport_settings=HttpTransportSettings.from_env(),
    )


def get_keycloak_client_wrapper(
    *,
    client_settings: ClientSettings | None = None,
    transport_settings: HttpTransportSettings | None = None,
) -> KeycloakHttpClientWrapperAsync:
    return KeycloakHttpClientWrapperAsync(
        client_settings=client_settings,
        transport_settings=transport_settings,
    )
