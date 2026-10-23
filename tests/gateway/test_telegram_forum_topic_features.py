"""Compatibility for Telegram forum-topic title routing and sender context."""

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.run_topics import GatewayTopicThreadsMixin
from gateway.session import SessionSource


def _source(chat_type: str, thread_id: str | None) -> SessionSource:
    return SessionSource(
        platform=Platform.TELEGRAM,
        user_id="u1",
        chat_id="-100123",
        user_name="Ada",
        chat_type=chat_type,
        thread_id=thread_id,
    )


def _runner() -> Any:
    runner = cast(Any, object.__new__(GatewayTopicThreadsMixin))
    runner.config = GatewayConfig(
        platforms={Platform.TELEGRAM: PlatformConfig(enabled=True, token="test")}
    )
    runner._TELEGRAM_GENERAL_TOPIC_IDS = frozenset({"", "1"})
    runner._session_db = None
    return runner


def test_group_forum_topics_are_renamable_but_general_and_excluded_topics_are_not():
    runner = _runner()
    assert runner._is_telegram_renamable_topic(_source("forum", "42"))
    assert not runner._is_telegram_renamable_topic(_source("forum", "1"))

    runner.config.platforms[Platform.TELEGRAM].extra["topic_rename_exclude_ids"] = ["42"]
    assert not runner._is_telegram_renamable_topic(_source("forum", "42"))


def test_dm_topics_keep_the_existing_topic_mode_gate():
    runner = _runner()
    runner._telegram_topic_mode_enabled = lambda source: False
    assert not runner._is_telegram_renamable_topic(_source("dm", "42"))
    runner._telegram_topic_mode_enabled = lambda source: True
    assert runner._is_telegram_renamable_topic(_source("dm", "42"))


@pytest.mark.asyncio
async def test_dm_topic_rename_keeps_existing_topic_mode_behavior():
    runner = _runner()
    runner._telegram_topic_mode_enabled = lambda source: True
    adapter = SimpleNamespace(rename_dm_topic=AsyncMock())
    runner._delivery_adapter_for = lambda source: adapter
    runner._sanitize_telegram_topic_title = lambda title: title

    await runner._rename_telegram_topic_for_session_title(
        _source("dm", "42"), "session-1", "DM Topic"
    )

    adapter.rename_dm_topic.assert_awaited_once_with(
        chat_id="-100123", thread_id="42", name="DM Topic",
    )


@pytest.mark.asyncio
async def test_forum_topic_rename_retries_one_telegram_retry_after(monkeypatch):
    class RetryAfterError(RuntimeError):
        retry_after: float = 3

    runner = _runner()
    error = RetryAfterError("rate limited")
    adapter = SimpleNamespace(rename_dm_topic=AsyncMock(side_effect=[error, None]))
    runner._delivery_adapter_for = lambda source: adapter
    runner._sanitize_telegram_topic_title = lambda title: title
    sleep = AsyncMock()
    monkeypatch.setattr("gateway.run_topics.asyncio.sleep", sleep)

    await runner._rename_telegram_topic_for_session_title(
        _source("forum", "42"), "session-1", "Forum Topic"
    )

    assert adapter.rename_dm_topic.await_count == 2
    sleep.assert_awaited_once_with(5.0)


def test_forum_topic_inbound_does_not_prepend_group_sender_name():
    from gateway.run_inbound import GatewayInboundMixin

    runner = cast(Any, SimpleNamespace(config=SimpleNamespace(
        group_sessions_per_user=False, thread_sessions_per_user=False,
    )))
    event = cast(Any, SimpleNamespace(channel_context=None))
    forum_source = _source("forum", "42")
    group_source = _source("group", None)

    assert GatewayInboundMixin._prefix_inbound_sender_context(
        runner, event, forum_source, "hello"
    ) == "hello"
    assert GatewayInboundMixin._prefix_inbound_sender_context(
        runner, event, group_source, "hello"
    ) == "[Ada] hello"
