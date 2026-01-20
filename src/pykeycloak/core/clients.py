import logging
from types import TracebackType
from typing import Any

from httpx import (
    AsyncClient,
    AsyncHTTPTransport,
    HTTPStatusError,
    RequestError,
    Response,
)

from .sanitizer import SensitiveDataSanitizer, get_sanitizer
from .settings import ClientSettings, HttpTransportSettings

logger = logging.getLogger(__name__)

from enum import Enum


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
            sanitizer: SensitiveDataSanitizer | None = None,
    ):
        transport_settings = transport_settings or HttpTransportSettings()
        transport = AsyncHTTPTransport(**transport_settings.to_dict())

        client_settings = client_settings or ClientSettings()
        client_settings.transport = transport

        self._sanitizer = sanitizer or get_sanitizer()

        self._client = AsyncClient(**client_settings.to_dict())

    @property
    def client(self) -> AsyncClient:
        return self._client

    @staticmethod
    def init_default_client() -> "KeycloakHttpClientWrapperAsync":
        return KeycloakHttpClientWrapperAsync()

    async def request(
            self, method: HttpMethod, url: str, raise_exception: bool = False, **kwargs: Any
    ) -> Response:
        try:
            logger.debug(
                "Request method: %s, url: %s kwargs %s",
                method,
                url,
                self._sanitizer.sanitize(kwargs),
            )

            response = await self.client.request(method=method.value, url=url, **kwargs)

            logger.debug(
                "Response method: %s, url: %s, content: %s, headers: %s",
                method,
                url,
                self._sanitizer.sanitize(response.json()),
                self._sanitizer.sanitize(dict(response.headers)),
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
        sanitizer=SensitiveDataSanitizer.from_env(),
    )


def get_keycloak_client_wrapper(
        *,
        client_settings: ClientSettings | None = None,
        transport_settings: HttpTransportSettings | None = None,
        sanitizer: SensitiveDataSanitizer | None = None,
) -> KeycloakHttpClientWrapperAsync:
    return KeycloakHttpClientWrapperAsync(
        client_settings=client_settings,
        transport_settings=transport_settings,
        sanitizer=sanitizer,
    )
