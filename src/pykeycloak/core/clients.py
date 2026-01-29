# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>
from enum import Enum
from types import TracebackType
from typing import Any, cast

from httpx import (
    AsyncClient,
    AsyncHTTPTransport,
)

from .. import logger
from .protocols import ResponseProtocol
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
        client: AsyncClient,
    ):
        self._client = client

    @property
    def client(self) -> AsyncClient:
        return self._client

    @staticmethod
    def init_default_client(client: AsyncClient) -> "KeycloakHttpClientWrapperAsync":
        return KeycloakHttpClientWrapperAsync(client=client)

    def log_client_config_before_request(self) -> None:
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

    async def request_async(
        self, method: HttpMethod, url: str, raise_exception: bool = False, **kwargs: Any
    ) -> ResponseProtocol:
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

        return cast(ResponseProtocol, response)

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

    async def close_async(self) -> None:
        await self._client.aclose()


def get_async_client(
    client_settings: ClientSettings | None = None,
    transport_settings: HttpTransportSettings | None = None,
) -> AsyncClient:
    transport_settings = transport_settings or HttpTransportSettings()
    transport = AsyncHTTPTransport(**transport_settings.to_dict())

    client_settings = client_settings or ClientSettings()
    client_settings.transport = transport

    return AsyncClient(**client_settings.to_dict())


def get_async_client_from_env() -> AsyncClient:
    return get_async_client(
        client_settings=ClientSettings.from_env(),
        transport_settings=HttpTransportSettings.from_env(),
    )


def get_keycloak_client_wrapper(
    *,
    client: AsyncClient,
) -> KeycloakHttpClientWrapperAsync:
    return KeycloakHttpClientWrapperAsync(
        client=client,
    )


def get_keycloak_client_wrapper_from_env() -> KeycloakHttpClientWrapperAsync:
    return KeycloakHttpClientWrapperAsync(
        client=get_async_client_from_env(),
    )
