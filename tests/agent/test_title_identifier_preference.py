"""Contracts for the title preference sent to the auxiliary model, not model-compliance tests.

The patch is deliberately prompt-only: these tests inspect the actual outgoing request and
exercise input bounds/output persistence without calling a model or inventing a postprocessor.
"""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agent import title_generator
from hermes_state import SessionDB


@pytest.fixture
def title_call(monkeypatch):
    response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
        content=json.dumps({"title": "Review topic rename behavior"})))])
    call = Mock(return_value=response)
    monkeypatch.setattr(title_generator, "call_llm", call)
    return call


def test_auxiliary_request_frontloads_only_referenced_identifiers(title_call):
    title_generator.generate_title("Review AGNT-280 and https://github.com/org/repo/pull/10789")
    request = title_call.call_args.kwargs
    system = " ".join(request["messages"][0]["content"].split())

    assert "Start with referenced PR numbers and ticket IDs" in system
    assert "PR#N|TICKET-ID Description" in system
    assert "PR#N Description" in system
    assert "TICKET-ID Description" in system
    assert "PRs before tickets" in system
    assert "first-mentioned order within each kind" in system
    assert "Never invent identifiers" in system
    assert "bare numbers are not PR references" in system
    assert "1-4 words describing the task" in system
    # Preferences belong only to this auxiliary call, never the conversation's user message.
    assert request["task"] == "title_generation"
    assert request["messages"][1]["content"] == "Review AGNT-280 and https://github.com/org/repo/pull/10789"
    assert "AGNT-280" not in system and "10789" not in system


@pytest.mark.parametrize("message,generated", [
    ("Review PR #10789 and AGNT-280", "PR#10789|AGNT-280 Review"),
    ("Review AGNT-280 then PR #10789", "PR#10789|AGNT-280 Review"),
    ("Review https://github.com/org/repo/pull/10789", "PR#10789 Review"),
    ("Implement BAC-918", "BAC-918 Fix frontend drift"),
    ("Review PR #12, PR #11, COD-2 and COD-1", "PR#12|PR#11|COD-2|COD-1 Review"),
    ("Investigate 10789 failures", "Investigate repeated failures"),
    ("Review https://example.com/reports/10789", "Review failure report"),
    # It is guidance, not a deterministic rewrite: a model may decline to use a prefix.
    ("Review PR #10789", "Review topic rename behavior"),
])
def test_model_title_is_persisted_without_identifier_rewriting(tmp_path, title_call, message, generated):
    title_call.return_value.choices[0].message.content = json.dumps({"title": generated})
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("session", source="cli")
        received = []
        title_generator.auto_title_session(db, "session", message, title_callback=lambda *args: received.append(args))
        assert db.get_session_title("session") == generated
        assert received == [(generated, "llm")]
        assert title_call.call_args.kwargs["messages"][1]["content"] == message
    finally:
        db.close()


def test_identifiers_outside_title_input_budget_are_not_extracted(title_call):
    message = "Investigate failures " + "x" * title_generator.MAX_TITLE_INPUT_CHARS + " PR #10789 AGNT-280"
    title_generator.generate_title(message)
    supplied = title_call.call_args.kwargs["messages"][1]["content"]
    assert len(supplied) == title_generator.MAX_TITLE_INPUT_CHARS
    assert "10789" not in supplied and "AGNT-280" not in supplied
