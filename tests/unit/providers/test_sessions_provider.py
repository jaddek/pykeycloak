# SPDX-License-Identifier: MIT
from unittest.mock import AsyncMock, MagicMock

import pytest

from pykeycloak.core.clients import HttpMethod
from pykeycloak.providers._sessions import SessionsProvider
from pykeycloak.providers.queries import PaginationQuery


@pytest.fixture
def sessions_provider(base, mock_access_token):
    return SessionsProvider(base=base, get_access_token=mock_access_token)


class TestGetClientSessionsAsync:
    @pytest.mark.asyncio
    async def test_gets_from_user_sessions_url(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.get_client_sessions_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "sessions" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_passes_query_params(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        query = PaginationQuery(max=10)
        await sessions_provider.get_client_sessions_async(query=query)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["params"] is not None


class TestGetUserSessionsAsync:
    @pytest.mark.asyncio
    async def test_url_contains_user_id(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.get_user_sessions_async("user-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "user-123" in call_kwargs["url"]
        assert "sessions" in call_kwargs["url"]


class TestDeleteSessionByIdAsync:
    @pytest.mark.asyncio
    async def test_deletes_session_by_id(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.delete_session_by_id_async("session-abc", is_offline=False)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.DELETE
        assert "session-abc" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_offline_param_true(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.delete_session_by_id_async("sid", is_offline=True)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["params"]["isOffline"] == "true"

    @pytest.mark.asyncio
    async def test_offline_param_false(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.delete_session_by_id_async("sid", is_offline=False)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["params"]["isOffline"] == "false"


class TestGetClientSessionsCountAsync:
    @pytest.mark.asyncio
    async def test_gets_session_count(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.get_client_sessions_count_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "session-count" in call_kwargs["url"]


class TestGetOfflineSessionsAsync:
    @pytest.mark.asyncio
    async def test_gets_offline_sessions(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.get_offline_sessions_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "offline-sessions" in call_kwargs["url"]


class TestGetOfflineSessionsCountAsync:
    @pytest.mark.asyncio
    async def test_gets_offline_session_count(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.get_offline_sessions_count_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "offline-session-count" in call_kwargs["url"]


class TestRemoveUserSessionsAsync:
    @pytest.mark.asyncio
    async def test_posts_to_user_logout_url(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.remove_user_sessions_async("user-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "user-123" in call_kwargs["url"]
        assert "logout" in call_kwargs["url"]


class TestLogoutAllUsersAsync:
    @pytest.mark.asyncio
    async def test_posts_to_logout_all_url(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.logout_all_users_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "logout-all" in call_kwargs["url"]


class TestGetClientSessionStatsAsync:
    @pytest.mark.asyncio
    async def test_gets_session_stats(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.get_client_session_stats_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "session-stats" in call_kwargs["url"]


class TestGetClientUserOfflineSessionsAsync:
    @pytest.mark.asyncio
    async def test_gets_offline_sessions_for_user(self, sessions_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await sessions_provider.get_client_user_offline_sessions_async("user-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "offline-sessions" in call_kwargs["url"]
