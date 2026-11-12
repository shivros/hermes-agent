"""Forum titles use the rename lane without enabling private-chat routing/lifecycle behavior."""

import asyncio
import weakref
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.run import GatewayRunner
from gateway.run_turn_runner import TurnRunner
from gateway.session import SessionSource, is_shared_multi_user_session
from hermes_state import AsyncSessionDB, SessionDB


class RecordingAdapter:
    def __init__(self, extra=None):
        self.config = PlatformConfig(enabled=True, extra=extra or {})
        self.rename_dm_topic = AsyncMock()


@pytest.fixture
def topic_runner(tmp_path):
    db = SessionDB(db_path=tmp_path / "state.db")
    db.apply_telegram_topic_migration()
    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig()
    runner.adapters = {Platform.TELEGRAM: RecordingAdapter()}
    runner._session_db = AsyncSessionDB(db)
    yield runner, db
    db.close()


def source(chat_type="forum", thread_id="42", **kwargs):
    return SessionSource(platform=Platform.TELEGRAM, chat_id="-100123", user_id="77",
                         chat_type=chat_type, thread_id=thread_id, **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("chat_type", ["forum", "group", "supergroup"])
async def test_group_topics_rename_without_enabling_dm_topic_routing(topic_runner, chat_type):
    runner, _db = topic_runner
    src = source(chat_type)

    await runner._rename_telegram_topic_for_session_title(src, "session", "  Fix   topic titles  ")

    runner.adapters[Platform.TELEGRAM].rename_dm_topic.assert_awaited_once_with(
        chat_id="-100123", thread_id="42", name="Fix topic titles")
    assert not runner._is_telegram_topic_lane(src)
    assert not runner._is_telegram_topic_root_lobby(src)
    assert runner._telegram_topic_new_header(src) is None
    assert is_shared_multi_user_session(src, thread_sessions_per_user=False)


@pytest.mark.asyncio
async def test_forum_model_title_callback_schedules_copy_on_receiving_bot(topic_runner, monkeypatch):
    runner, _db = topic_runner
    receiver = RecordingAdapter()
    runner._profile_adapters = {"receiver": {Platform.TELEGRAM: receiver}}
    src = source(profile="satellite")
    src._transport_adapter_ref = weakref.ref(receiver)
    tasks = []

    def schedule(coro, loop, **kwargs):
        task = loop.create_task(coro)
        tasks.append(task)
        return task

    monkeypatch.setattr("gateway.run.safe_schedule_threadsafe", schedule)
    holder = object.__new__(TurnRunner)
    holder._runner = runner
    agent = SimpleNamespace(session_id="session")
    holder._attach_session_title_callback(agent, SimpleNamespace(source=src, session_key="key"))

    assert callable(getattr(agent, "_on_session_title", None))
    agent._on_session_title("Temporary title", "derived")
    assert tasks == []
    agent._on_session_title("Semantic forum title", "llm")
    await asyncio.gather(*tasks)

    receiver.rename_dm_topic.assert_awaited_once_with(
        chat_id="-100123", thread_id="42", name="Semantic forum title")
    runner.adapters[Platform.TELEGRAM].rename_dm_topic.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("thread_id", [None, "", "0", "1"])
async def test_general_topics_never_rename_even_with_empty_exclusions(topic_runner, thread_id):
    runner, _db = topic_runner
    runner.adapters[Platform.TELEGRAM].config.extra["topic_rename_exclude_ids"] = []
    await runner._rename_telegram_topic_for_session_title(source(thread_id=thread_id), "session", "Title")
    runner.adapters[Platform.TELEGRAM].rename_dm_topic.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("chat_type", ["forum", "dm"])
async def test_detached_topic_never_renames(topic_runner, chat_type):
    runner, db = topic_runner
    db.enable_telegram_topic_mode(chat_id="-100123", user_id="77")
    await runner._rename_telegram_topic_for_session_title(
        source(chat_type, detached_route="agent:main:detached:session"), "session", "Title")
    runner.adapters[Platform.TELEGRAM].rename_dm_topic.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("extra", [
    {"disable_topic_auto_rename": True},
    {"disable_topic_auto_rename": "true"},
    {"topic_rename_exclude_ids": [42]},
    {"topic_rename_exclude_ids": ["42"]},
])
async def test_receiving_adapter_owns_rename_opt_out(topic_runner, extra):
    runner, _db = topic_runner
    receiver = RecordingAdapter(extra)
    runner._profile_adapters = {"receiver": {Platform.TELEGRAM: receiver}}
    src = source(profile="satellite")
    src._transport_adapter_ref = weakref.ref(receiver)
    await runner._rename_telegram_topic_for_session_title(src, "session", "Title")
    receiver.rename_dm_topic.assert_not_awaited()
    runner.adapters[Platform.TELEGRAM].rename_dm_topic.assert_not_awaited()


@pytest.mark.asyncio
async def test_launch_bot_exclusion_does_not_disable_receiving_bot(topic_runner):
    runner, _db = topic_runner
    runner.adapters[Platform.TELEGRAM].config.extra.update(
        disable_topic_auto_rename=True, topic_rename_exclude_ids=["42"])
    receiver = RecordingAdapter()
    runner._profile_adapters = {"receiver": {Platform.TELEGRAM: receiver}}
    src = source(profile="satellite")
    src._transport_adapter_ref = weakref.ref(receiver)
    await runner._rename_telegram_topic_for_session_title(src, "session", "Title")
    receiver.rename_dm_topic.assert_awaited_once()


@pytest.mark.asyncio
async def test_forum_stale_binding_checked_in_routed_profile(topic_runner):
    runner, db = topic_runner
    src = source(profile="satellite")
    receiver = RecordingAdapter()
    runner._profile_adapters = {"receiver": {Platform.TELEGRAM: receiver}}
    src._transport_adapter_ref = weakref.ref(receiver)
    for sid in ("default-session", "satellite-session"):
        db.create_session(sid, source="telegram")
    for profile, sid in (("default", "default-session"), ("satellite", "satellite-session")):
        db.bind_telegram_topic(chat_id=src.chat_id, thread_id=src.thread_id, user_id=src.user_id,
                               session_key=f"agent:{profile}:telegram:group:-100123:42", session_id=sid,
                               profile_name=profile)

    await runner._rename_telegram_topic_for_session_title(src, "default-session", "Stale title")
    receiver.rename_dm_topic.assert_not_awaited()
    await runner._rename_telegram_topic_for_session_title(src, "satellite-session", "Current title")
    receiver.rename_dm_topic.assert_awaited_once_with(
        chat_id="-100123", thread_id="42", name="Current title")


@pytest.mark.asyncio
async def test_unreadable_binding_fails_closed(topic_runner):
    runner, _db = topic_runner
    runner._session_db = SimpleNamespace(get_telegram_topic_binding=AsyncMock(side_effect=RuntimeError("offline")))
    await runner._rename_telegram_topic_for_session_title(source(), "session", "Title")
    runner.adapters[Platform.TELEGRAM].rename_dm_topic.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_declared_dm_topic_keeps_name(topic_runner):
    runner, db = topic_runner
    db.enable_telegram_topic_mode(chat_id="-100123", user_id="77")

    class OperatorAdapter(RecordingAdapter):
        def _get_dm_topic_info(self, chat_id, thread_id):
            return {"name": "Fixed name"}

    adapter = OperatorAdapter()
    runner.adapters[Platform.TELEGRAM] = adapter
    await runner._rename_telegram_topic_for_session_title(source("dm"), "session", "Title")
    adapter.rename_dm_topic.assert_not_awaited()


class RetryAfter(Exception):
    def __init__(self, delay):
        self.retry_after = delay
        super().__init__("Flood control exceeded")


@pytest.mark.asyncio
@pytest.mark.parametrize("delay,seconds", [(2.5, 2.5), (timedelta(seconds=3), 3), (60, 60)])
async def test_flood_control_waits_requested_delay_then_retries_once(topic_runner, monkeypatch, delay, seconds):
    runner, _db = topic_runner
    adapter = runner.adapters[Platform.TELEGRAM]
    adapter.rename_dm_topic.side_effect = [RetryAfter(delay), None]
    sleep = AsyncMock()
    monkeypatch.setattr("gateway.run_topics.asyncio.sleep", sleep)

    await runner._rename_telegram_topic_for_session_title(source(), "session", "Title")

    sleep.assert_awaited_once_with(seconds)
    assert adapter.rename_dm_topic.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("delay", [61, timedelta(seconds=90), float("inf"), float("nan"), "invalid"])
async def test_long_or_invalid_flood_control_never_retries_early(topic_runner, monkeypatch, delay):
    runner, _db = topic_runner
    adapter = runner.adapters[Platform.TELEGRAM]
    adapter.rename_dm_topic.side_effect = RetryAfter(delay)
    sleep = AsyncMock()
    monkeypatch.setattr("gateway.run_topics.asyncio.sleep", sleep)
    await runner._rename_telegram_topic_for_session_title(source(), "session", "Title")
    assert adapter.rename_dm_topic.await_count == 1
    sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_second_flood_control_is_not_retried(topic_runner, monkeypatch):
    runner, _db = topic_runner
    adapter = runner.adapters[Platform.TELEGRAM]
    adapter.rename_dm_topic.side_effect = RetryAfter(2)
    sleep = AsyncMock()
    monkeypatch.setattr("gateway.run_topics.asyncio.sleep", sleep)
    await runner._rename_telegram_topic_for_session_title(source(), "session", "Title")
    assert adapter.rename_dm_topic.await_count == 2
    sleep.assert_awaited_once_with(2)


@pytest.mark.asyncio
@pytest.mark.parametrize("changed_guard", ["binding", "disable", "detached"])
async def test_retry_rechecks_ownership_after_wait(topic_runner, monkeypatch, changed_guard):
    runner, db = topic_runner
    adapter = runner.adapters[Platform.TELEGRAM]
    adapter.rename_dm_topic.side_effect = [RetryAfter(2), None]
    src = source()

    async def wait(_delay):
        if changed_guard == "binding":
            db.create_session("new-session", source="telegram")
            db.bind_telegram_topic(chat_id=src.chat_id, thread_id=src.thread_id, user_id=src.user_id,
                                   session_key="key", session_id="new-session")
        elif changed_guard == "disable":
            adapter.config.extra["disable_topic_auto_rename"] = True
        else:
            src.detached_route = "agent:main:detached:session"

    sleep = AsyncMock(side_effect=wait)
    monkeypatch.setattr("gateway.run_topics.asyncio.sleep", sleep)
    await runner._rename_telegram_topic_for_session_title(src, "session", "Title")
    sleep.assert_awaited_once_with(2)
    assert adapter.rename_dm_topic.await_count == 1
