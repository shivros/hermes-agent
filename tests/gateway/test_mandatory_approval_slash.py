"""Typed blanket grants must not become individually targeted mandatory approvals."""
import pytest

from tests.gateway.test_approve_deny_commands import _make_event, _make_runner, _make_source
from tools import approval
from tools.approval_gateway_wait import _ApprovalEntry


@pytest.fixture
def pending(monkeypatch):
    runner = _make_runner()
    session = runner._session_key_for_source(_make_source())
    entries = [
        _ApprovalEntry({'command': 'bash large.sh', 'once_only': True,
                        'allow_session': False, 'allow_permanent': False}),
        _ApprovalEntry({'command': 'bash large.sh', 'once_only': True,
                        'allow_session': False, 'allow_permanent': False}),
        _ApprovalEntry({'command': 'ordinary'}),
    ]
    monkeypatch.setitem(approval._gateway_queues, session, entries.copy())
    return runner, session, entries


@pytest.mark.asyncio
@pytest.mark.parametrize('scope', ['', ' session', ' always'])
async def test_typed_approve_all_leaves_mandatory_requests_pending(pending, scope):
    runner, session, entries = pending
    await runner._handle_approve_command(_make_event('/approve all' + scope))
    assert all(not e.event.is_set() for e in entries[:2])
    assert entries[2].event.is_set()
    assert len(approval.list_gateway_approvals(session)) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('scope', ['', ' session', ' always'])
async def test_typed_individual_approve_answers_only_one_mandatory_request(pending, scope):
    runner, session, entries = pending
    await runner._handle_approve_command(_make_event('/approve' + scope))
    assert entries[0].event.is_set()
    assert all(not e.event.is_set() for e in entries[1:])
    assert len(approval.list_gateway_approvals(session)) == 2


@pytest.mark.asyncio
async def test_typed_deny_all_still_denies_every_request(pending):
    runner, session, entries = pending
    await runner._handle_deny_command(_make_event('/deny all'))
    assert all(e.event.is_set() and e.result == 'deny' for e in entries)
    assert not approval.list_gateway_approvals(session)


def test_batch_target_with_request_id_cannot_grant_mandatory_review(pending):
    _, session, entries = pending
    count = approval.resolve_gateway_approval(session, 'once', resolve_all=True,
        request_id=entries[0].data['request_id'])
    assert count == 0 and not entries[0].event.is_set()
