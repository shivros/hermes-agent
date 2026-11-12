"""Mandatory review keeps SQLite locks, invocation consent and dispatch cwd intact."""
import inspect
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest
from cron import lifecycle_guard as lifecycle
from hermes_cli import sqlite_safe_read as safe
from tools import approval, approval_context
from tools import terminal_tool as terminal, terminal_tool_background as background_module
from tools import terminal_tool_guards as guards


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setenv('HERMES_INTERACTIVE', '1')
    for key in ('HERMES_EXEC_ASK', 'HERMES_GATEWAY_SESSION', 'HERMES_CRON_SESSION', 'HERMES_YOLO_MODE'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr('tools.process_registry._is_supervised_gateway_process', lambda: True)
    monkeypatch.setattr(approval_context, '_get_approval_mode', lambda: 'manual')
    monkeypatch.setattr(approval_context, '_get_approval_transport_config', lambda: ('builtin', None))
    monkeypatch.setattr(approval_context, '_get_approval_timeout', lambda: 20)
    monkeypatch.setattr(terminal, 'get_session_cwd', lambda key: None)
    env = SimpleNamespace(cwd=str(tmp_path), env={}, calls=[])
    script = tmp_path / 'large.sh'
    script.write_text('# opaque review padding\n' * 50000 + "printf 'QUALITY_REVIEWED\\n'\n")
    assert script.stat().st_size > lifecycle._MAX_REFERENCED_SCRIPT_BYTES
    def execute(command, **kwargs):
        proc = subprocess.run(['/bin/bash', '-c', command], cwd=kwargs['cwd'],
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=10, check=False)
        env.calls.append((command, kwargs['cwd'], proc.stdout, proc.returncode))
        return {'output': proc.stdout + proc.stderr, 'returncode': proc.returncode}
    env.execute = execute
    monkeypatch.setattr(terminal, '_get_env_config', lambda: {
        'env_type': 'local', 'cwd': str(tmp_path), 'timeout': 30, 'lifetime_seconds': 3600})
    monkeypatch.setattr(terminal, '_acquire_env', lambda *a: env)
    return script, env


def competitor(db):
    code = """import sqlite3, sys
c=sqlite3.connect(sys.argv[1], timeout=0)
try:
    c.execute('BEGIN IMMEDIATE')
    print('ACQUIRED')
    c.rollback()
except sqlite3.OperationalError as e:
    print('LOCKED' if 'locked' in str(e) else 'ERROR:' + str(e))
c.close()
"""
    return subprocess.check_output([sys.executable, '-c', code, str(db)], text=True,
        env={'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME']}, timeout=10).strip()


@pytest.mark.platforms('posix')
@pytest.mark.parametrize('entry', ['identity_helper', 'gateway_preflight'])
def test_identity_hash_must_not_drop_concurrently_opened_sqlite_lock(sandbox, monkeypatch, entry):
    script, env = sandbox
    db = script.with_name('state.db')
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE payload(value BLOB)')
    conn.execute('INSERT INTO payload VALUES (zeroblob(1100000))')
    conn.commit()
    conn.close()
    begin = threading.Event()
    ready = threading.Event()
    release = threading.Event()
    state = {}
    def holder():
        try:
            assert begin.wait(10)
            c = safe.connect_tracked(db, timeout=0)
            c.execute('BEGIN IMMEDIATE')
            state['conn'] = c
            ready.set()
            assert release.wait(20)
            c.rollback()
            c.close()
        except BaseException as exc:
            state['error'] = repr(exc)
            ready.set()
    thread = threading.Thread(target=holder, daemon=True)
    thread.start()
    original = safe.has_live_connection
    raced = []
    def race(path):
        answer = original(path)
        if (Path(path) == db and not answer and not raced
                and inspect.currentframe().f_back.f_code.co_name == '_review_file_identity'):
            raced.append(True)
            begin.set()
            assert ready.wait(10) and 'error' not in state, state
            state['before'] = competitor(db)
        return answer
    monkeypatch.setattr(safe, 'has_live_connection', race)
    try:
        if entry == 'identity_helper':
            try:
                result = guards._review_file_identity(db)
            except ValueError as exc:
                result = str(exc)
        else:
            result = guards.gateway_lifecycle_block(command='bash state.db', env=env, env_type='local',
                cwd=str(db.parent), workdir=None, session_key='quality-sqlite')
        assert raced and state['before'] == 'LOCKED', state
        after = competitor(db)
        print('SQLITE_ENTRY', entry, 'BEFORE', state['before'], 'AFTER', after,
              'ORIGINAL_IN_TRANSACTION', state['conn'].in_transaction,
              'TRACKED_LIVE', original(db), 'GUARD_RESULT_TYPE', type(result).__name__)
        assert after == 'LOCKED', 'new identity raw close cancelled the still-live tracked SQLite RESERVED lock'
    finally:
        begin.set()
        release.set()
        thread.join(10)
        assert not thread.is_alive() and 'error' not in state, state


@pytest.mark.platforms('posix')
@pytest.mark.parametrize('choice', ['once', 'session', 'always', 'deny'])
def test_concurrent_mandatory_reviews_need_separate_human_answers(sandbox, monkeypatch, choice):
    from tools.registry import registry
    _, env = sandbox
    session = 'quality-coalesced-' + choice
    monkeypatch.setattr(approval, 'get_current_session_key', lambda *a, **kw: session)
    monkeypatch.setattr(approval_context, 'get_current_session_key', lambda *a, **kw: session)
    monkeypatch.setattr(approval, '_presence', lambda cb=None: (None, False, True, True))
    for name in ('_is_cron_approval_context', '_is_single_query_approval_context', '_is_unattended_platform_approval_context'):
        monkeypatch.setattr(approval, name, lambda: False)
    monkeypatch.setattr(terminal, '_get_approval_callback', lambda: None)
    first_prompt = threading.Event()
    second_prompt = threading.Event()
    settled = threading.Event()
    prompts, results, errors = [], [], []
    lock = threading.Lock()
    def notify(data):
        with lock:
            prompts.append(data)
            first_prompt.set()
            if len(prompts) > 1:
                second_prompt.set()
    monkeypatch.setattr(approval, '_gateway_notify_cb', lambda key: notify)
    def run():
        try:
            result = json.loads(registry.dispatch('terminal', {'command': 'bash large.sh'}))
            with lock:
                results.append(result)
                if len(results) == 2:
                    settled.set()
        except BaseException as exc:
            errors.append(repr(exc))
            settled.set()
    threads = [threading.Thread(target=run, daemon=True) for _ in range(2)]
    try:
        threads[0].start()
        assert first_prompt.wait(20)
        threads[1].start()
        assert second_prompt.wait(5), 'each mandatory invocation needs its own prompt'
        assert len(prompts) == 2
        assert prompts[0]['request_id'] != prompts[1]['request_id']
        assert prompts[0]['pattern_key'] != prompts[1]['pattern_key']
        assert all(not p['allow_session'] and not p['allow_permanent'] for p in prompts)
        assert approval.resolve_gateway_approval(session, choice, request_id=prompts[0]['request_id']) == 1
        # Replaying a stale answer cannot release the other invocation.
        assert approval.resolve_gateway_approval(session, choice, request_id=prompts[0]['request_id']) == 0
        assert approval.resolve_gateway_approval(session, 'deny', request_id=prompts[1]['request_id']) == 1
        prompt_count_after_one_answer = len(prompts)
        for thread in threads:
            thread.join(20)
        assert not errors and all(not t.is_alive() for t in threads), errors
        executed = len(env.calls)
        print('COALESCED_CHOICE', choice, 'PROMPTS_AFTER_ONE_ANSWER', prompt_count_after_one_answer,
              'ACTUAL_EXECUTIONS', executed, 'STDOUTS', [c[2].strip() for c in env.calls],
              'RESULTS', results)
        assert executed == (0 if choice == 'deny' else 1) and prompt_count_after_one_answer == 2, 'a broad legacy answer covered multiple mandatory one-shot executions'
    finally:
        approval.resolve_gateway_approval(session, 'deny', resolve_all=True)
        for thread in threads:
            if thread.ident:
                thread.join(10)


@pytest.mark.platforms('posix')
@pytest.mark.parametrize('background', [False, True])
@pytest.mark.parametrize('change_at', [1, 2])
def test_reviewed_cwd_must_be_the_dispatched_cwd(sandbox, monkeypatch, background, change_at):
    from tools.registry import registry
    script, env = sandbox
    other = script.parent / 'other'
    other.mkdir()
    (other / 'large.sh').write_text("printf 'UNREVIEWED_OTHER_CWD\\n'\n")
    state = {'cwd': str(script.parent), 'approved': False, 'changed': False, 'validations': 0}
    monkeypatch.setattr(terminal, 'get_session_cwd', lambda key: state['cwd'])
    def approve(*args, **kwargs):
        state['approved'] = True
        return 'once'
    monkeypatch.setattr(terminal, '_get_approval_callback', lambda: approve)
    real_valid = guards.LifecycleScanReview.valid_for
    def valid(self, command, cwd):
        answer = real_valid(self, command, cwd)
        if answer and state['approved']:
            state['validations'] += 1
        if answer and state['approved'] and state['validations'] == change_at:
            # A different completed command in this session updates its cwd immediately after
            # post-answer validation. No path/file mutation and no shell final-open race.
            state.update(cwd=str(other), changed=True)
        return answer
    monkeypatch.setattr(guards.LifecycleScanReview, 'valid_for', valid)
    spawned = []
    def spawn(process_registry, **kwargs):
        proc = subprocess.run(['/bin/bash', '-c', kwargs['command']], cwd=kwargs['cwd'],
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=10, check=False)
        spawned.append((kwargs['cwd'], proc.stdout, proc.returncode))
        return SimpleNamespace(id='quality-harmless-spawn', pid=proc.pid if hasattr(proc, 'pid') else 0)
    monkeypatch.setattr(background_module, '_spawn', spawn)
    result = json.loads(registry.dispatch('terminal', {'command': 'bash large.sh', 'background': background}))
    print('CWD_BACKGROUND', background, 'BOUND_CWD', str(script.parent), 'STATE', state,
          'SPAWNED', spawned, 'FOREGROUND_CALLS', env.calls, 'RESULT', result)
    assert state['changed'], 'review must reach the actual dispatch consumer'
    if change_at == 1:
        assert not spawned and not env.calls and result.get('status') == 'blocked'
    else:
        # Once the final consumer validates, it must use that exact value, not resolve again.
        assert result['exit_code'] == 0
        executed = spawned if background else [(c[1], c[2], c[3]) for c in env.calls]
        assert executed == [(str(script.parent), 'QUALITY_REVIEWED\n', 0)]


@pytest.mark.parametrize('choice', ['once', 'session', 'always'])
def test_blanket_approval_cannot_settle_mandatory_invocations(sandbox, monkeypatch, choice):
    from tools import approval_gateway_wait as wait

    script, env = sandbox
    session = 'mandatory-blanket-' + choice
    review = guards.gateway_lifecycle_block(command='bash large.sh', env=env, env_type='local',
        cwd=str(script.parent), workdir=None, session_key=session)
    monkeypatch.setattr(approval, 'get_current_session_key', lambda: session)
    monkeypatch.setattr(approval, '_presence', lambda cb=None: (None, False, True, True))
    monkeypatch.setattr(approval, '_persist_choice', lambda *a: pytest.fail('one-shot cannot persist'))
    seen = []

    def notify(data):
        # Include an ordinary request to prove /approve all still works for that class.
        ordinary = wait._ApprovalEntry({'command': 'ordinary', 'pattern_keys': ['ordinary']})
        with approval._lock:
            approval._gateway_queues[session].append(ordinary)
        seen.append(approval.resolve_gateway_approval(session, choice, resolve_all=True))
        assert ordinary.result == choice
        assert approval.list_gateway_approvals(session)[0]['request_id'] == data['request_id']
        assert approval.resolve_gateway_approval(session, 'deny', request_id=data['request_id']) == 1

    monkeypatch.setattr(approval, '_gateway_notify_cb', lambda key: notify)
    result = approval.check_all_command_guards('bash large.sh', 'local', required_review=review)
    assert not result['approved'] and seen == [1]


@pytest.mark.parametrize('surface', ['cli', 'plugin'])
def test_mandatory_invocation_correlation_reaches_prompt_bridges(sandbox, monkeypatch, surface):
    from tools import approval_prompt

    script, env = sandbox
    review = guards.gateway_lifecycle_block(command='bash large.sh', env=env, env_type='local',
        cwd=str(script.parent), workdir=None, session_key='bridge-review')
    seen = []
    monkeypatch.setattr(approval_context, '_fire_approval_hook', lambda name, **kw: seen.append((name, kw)))
    monkeypatch.setattr(approval, '_persist_choice', lambda *a: pytest.fail('one-shot cannot persist'))
    if surface == 'plugin':
        monkeypatch.setattr(approval_context, '_get_approval_transport_config', lambda: ('phone', None))
        monkeypatch.setattr(approval_prompt, 'get_plugin_manager', lambda: SimpleNamespace(
            get_approval_transport=lambda name: SimpleNamespace(present=lambda req: req.respond('once'))))
    for _ in range(2):
        result = approval.check_all_command_guards('bash large.sh', 'local', required_review=review,
            approval_callback=lambda *a, **kw: 'always')
        assert result['approved']
    requests = [kw for name, kw in seen if name == 'pre_approval_request']
    assert len(requests) == 2
    assert requests[0]['pattern_key'] != requests[1]['pattern_key']


@pytest.mark.platforms('posix')
def test_tracked_connection_cannot_open_until_hash_descriptor_closes(sandbox, monkeypatch):
    script, _ = sandbox
    db = script.with_name('hash.db')
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE payload(value BLOB)')
        conn.execute('INSERT INTO payload VALUES (zeroblob(1100000))')
    conn.close()
    begin, attempting, ready, release, closed = [threading.Event() for _ in range(5)]
    state = {}

    def opener(*args, **kwargs):
        state['opened_after_raw_close'] = closed.is_set()
        return sqlite3.connect(*args, **kwargs)

    def holder():
        try:
            assert begin.wait(10)
            # Synchronize an actual competing lifecycle acquisition, without a timing-based
            # negative wait. A connection must be excluded while this raw fd remains open.
            acquired = safe._live_lock.acquire(blocking=False)
            state['lifecycle_excluded'] = not acquired
            if acquired:
                safe._live_lock.release()
            attempting.set()
            c = safe.connect_tracked(db, connect_fn=opener, timeout=0)
            c.execute('BEGIN IMMEDIATE')
            ready.set()
            assert release.wait(20)
            c.rollback()
            c.close()
        except BaseException as exc:
            state['error'] = repr(exc)
            ready.set()

    original_open, original_fdopen = os.open, os.fdopen

    def open_file(path, *args, **kwargs):
        fd = original_open(path, *args, **kwargs)
        if Path(path) == db:
            state['fd'] = fd
            begin.set()
            assert attempting.wait(10)
        return fd

    class HashSource:
        def __init__(self, source):
            self.source = source

        def __enter__(self):
            return self.source

        def __exit__(self, *exc):
            self.source.close()
            closed.set()

    def fdopen(fd, *args, **kwargs):
        source = original_fdopen(fd, *args, **kwargs)
        return HashSource(source) if fd == state.get('fd') else source

    monkeypatch.setattr(os, 'open', open_file)
    monkeypatch.setattr(os, 'fdopen', fdopen)
    thread = threading.Thread(target=holder, daemon=True)
    thread.start()
    try:
        guards._review_file_identity(db)
        assert ready.wait(10) and 'error' not in state, state
        assert state['lifecycle_excluded'], 'hash did not own the SQLite connection lifecycle'
        assert state['opened_after_raw_close'], 'tracked sqlite opened while raw hash descriptor was live'
        assert competitor(db) == 'LOCKED'
    finally:
        begin.set()
        release.set()
        thread.join(10)
        assert not thread.is_alive() and 'error' not in state, state


@pytest.mark.platforms('posix')
@pytest.mark.parametrize('background', [False, True])
def test_delegated_child_review_is_checked_against_its_own_cwd(sandbox, monkeypatch, background):
    """A delegated child's cwd is recorded under its task id, not the parent session key it
    inherits. The guard binds the review to that cwd, so the post-answer check must read the
    same key: a mismatch would block every approved command after the human said yes."""
    from tools.registry import registry
    script, env = sandbox
    child = script.parent / 'child'
    child.mkdir()
    (child / 'large.sh').write_text(script.read_text())
    script.unlink()
    cwds = {'quality-parent-session': str(script.parent), 'quality-child-task': str(child)}
    monkeypatch.setattr(terminal, 'get_session_cwd', lambda key: cwds.get(key))
    monkeypatch.setattr('agent.delegation_context.is_delegated_child_context', lambda: True)
    monkeypatch.setattr(approval, 'get_current_session_key', lambda default=None: 'quality-parent-session')
    monkeypatch.setattr(terminal, '_get_approval_callback', lambda: lambda *args, **kwargs: 'once')
    spawned = []
    def spawn(process_registry, **kwargs):
        proc = subprocess.run(['/bin/bash', '-c', kwargs['command']], cwd=kwargs['cwd'],
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=10, check=False)
        spawned.append((kwargs['cwd'], proc.stdout, proc.returncode))
        return SimpleNamespace(id='quality-harmless-spawn', pid=0, cwd=kwargs['cwd'])
    monkeypatch.setattr(background_module, '_spawn', spawn)
    # The registry injects task_id from the delegation context rather than a tool parameter.
    result = json.loads(terminal.terminal_tool(
        'bash large.sh', background=background, task_id='quality-child-task'))
    assert result['exit_code'] == 0, result
    executed = spawned if background else [(cwd, out, code) for _, cwd, out, code in env.calls]
    assert executed == [(str(child), 'QUALITY_REVIEWED\n', 0)]


@pytest.mark.platforms('posix')
@pytest.mark.parametrize('background', [False, True])
def test_reviewed_command_disallows_cwd_fallback_at_both_dispatch_boundaries(sandbox, monkeypatch, background):
    """Consent is bound to one cwd. An unreviewed command may fall back to a parent directory
    when the session cwd has disappeared; a reviewed one must not. This proves the flag reaches
    the environment dispatch and the spawn boundary and that both commands really ran in the
    reviewed cwd; the local spawn's refusal itself is proved by
    test_reviewed_command_never_falls_back_to_a_parent_directory."""
    from tools.registry import registry
    script, env = sandbox
    (script.parent / 'small.sh').write_text("printf 'SMALL_UNREVIEWED\\n'\n")
    monkeypatch.setattr(terminal, '_get_approval_callback', lambda: lambda *args, **kwargs: 'once')
    fallbacks = []
    execute = env.execute
    def recording_execute(command, **kwargs):
        fallbacks.append(kwargs.get('allow_cwd_fallback'))
        return execute(command, **kwargs)
    env.execute = recording_execute
    def spawn(process_registry, **kwargs):
        fallbacks.append(kwargs.get('allow_cwd_fallback'))
        proc = subprocess.run(['/bin/bash', '-c', kwargs['command']], cwd=kwargs['cwd'],
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=10, check=False)
        assert proc.returncode == 0, proc.stderr  # the reviewed script really ran, in kwargs['cwd']
        return SimpleNamespace(id='quality-harmless-spawn', pid=0, cwd=kwargs['cwd'])
    monkeypatch.setattr(background_module, '_spawn', spawn)
    reviewed = json.loads(registry.dispatch('terminal', {'command': 'bash large.sh', 'background': background}))
    unreviewed = json.loads(registry.dispatch('terminal', {'command': 'bash small.sh', 'background': background}))
    assert reviewed['exit_code'] == 0 and unreviewed['exit_code'] == 0, (reviewed, unreviewed)
    assert fallbacks == [False, True]


@pytest.mark.platforms('posix')
def test_reviewed_command_never_falls_back_to_a_parent_directory(sandbox, monkeypatch):
    """Consent is bound to one cwd. An unreviewed command may fall back to a parent directory
    when the session cwd has disappeared or became unenterable; a reviewed one must fail instead
    of running an opaque script from a directory nobody reviewed. The local spawn picks a safe
    cwd itself (process_registry._resolve_safe_cwd), so the refusal has to happen before it.
    The real _spawn stays in the loop; only the registry is stood in for."""
    from tools import process_registry as registry_module
    from tools.environments.local import _resolve_safe_cwd
    script, env = sandbox
    session = script.parent / 'session'
    session.mkdir()
    (script.parent / 'small.sh').write_text("printf 'SMALL_UNREVIEWED\\n'\\n")
    env.cwd = str(session)
    monkeypatch.setattr(terminal, '_get_env_config', lambda: {
        'env_type': 'local', 'cwd': str(session), 'timeout': 30, 'lifetime_seconds': 3600})

    def approve(*args, **kwargs):
        session.chmod(0o600)  # the reviewed directory becomes unenterable after consent
        return 'once'
    monkeypatch.setattr(terminal, '_get_approval_callback', lambda: approve)
    ran_in = []

    def spawn_local(**kwargs):
        # What the real registry does with a cwd it cannot enter: the nearest usable ancestor.
        safe = _resolve_safe_cwd(kwargs['cwd'] or os.getcwd())
        proc = subprocess.run(['/bin/bash', '-c', kwargs['command']], cwd=safe,
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=10, check=False)
        ran_in.append((safe, proc.returncode))
        return SimpleNamespace(id='quality-harmless-spawn', pid=0, cwd=safe)
    monkeypatch.setattr(registry_module, 'process_registry', SimpleNamespace(spawn_local=spawn_local))
    reviewed = json.loads(terminal.terminal_tool(f'bash {script}', background=True))
    assert ran_in == [], ran_in  # nothing started: the reviewed cwd is no longer enterable
    assert reviewed['exit_code'] != 0 and 'no fallback is allowed' in reviewed['error'], reviewed
    # The fallback stays for unreviewed commands: same dead cwd, no review, parent directory.
    unreviewed = json.loads(terminal.terminal_tool(f'bash {script.parent / "small.sh"}', background=True))
    assert unreviewed['exit_code'] == 0, unreviewed
    assert ran_in == [(str(script.parent), 0)], ran_in
