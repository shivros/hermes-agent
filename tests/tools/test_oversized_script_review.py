"""Supervised oversized-file exceptions require fresh human consent, never replay flags."""
import json
from types import SimpleNamespace

import pytest

from cron import lifecycle_guard as lifecycle
from tools import approval, approval_context, terminal_tool as terminal
from tools import terminal_tool_guards as guards


@pytest.fixture
def supervised(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, "_MAX_REFERENCED_SCRIPT_BYTES", 128)
    monkeypatch.setattr("tools.process_registry._is_supervised_gateway_process", lambda: True)
    monkeypatch.setattr(terminal, "get_session_cwd", lambda key: None)
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    for key in ("HERMES_EXEC_ASK", "HERMES_GATEWAY_SESSION", "HERMES_CRON_SESSION", "HERMES_YOLO_MODE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(approval_context, "_get_approval_mode", lambda: "manual")
    script = tmp_path / "large.sh"
    script.write_text("# reviewed opaque contents\n" * 20)
    env = SimpleNamespace(cwd=str(tmp_path))
    def check(command="bash large.sh", **kw):
        return guards.gateway_lifecycle_block(command=command, env=env, env_type=kw.get("env_type", "local"),
            cwd=str(tmp_path), workdir=kw.get("workdir"), session_key="review-test")
    return script, env, check


def test_only_per_file_size_is_structured(supervised, monkeypatch):
    script, _, _ = supervised
    unsafe, refusal = lifecycle.scan_gateway_lifecycle(f"bash {script}")
    assert unsafe
    assert getattr(refusal, "reason", None) == "file_size"
    monkeypatch.setattr(lifecycle, "_MAX_LIFECYCLE_SCAN_BYTES", 32)
    small = script.with_name("small.sh")
    small.write_text("# padding\n" * 6)
    unsafe, refusal = lifecycle.scan_gateway_lifecycle("bash small.sh", cwd=str(script.parent))
    assert unsafe and getattr(refusal, "reason", None) != "file_size"


def test_review_continues_scanning_other_references(supervised):
    script, _, check = supervised
    review = check()
    assert isinstance(review, guards.LifecycleScanReview)
    other = script.with_name("stop.sh")
    other.write_text("hermes gateway stop\n")
    assert isinstance(check("bash large.sh; bash stop.sh"), str)


@pytest.mark.parametrize("mode", ["manual", "smart", "off"])
@pytest.mark.parametrize("force", [False, True])
def test_force_and_modes_cannot_skip_review(supervised, monkeypatch, mode, force):
    _, _, check = supervised
    review = check()
    calls = []
    monkeypatch.setattr(approval_context, "_get_approval_mode", lambda: mode)
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    monkeypatch.setattr(approval, "_yolo_active", lambda: True)
    monkeypatch.setattr(terminal, "_get_approval_callback", lambda: lambda *a, **kw: calls.append(kw) or "once")
    for _ in range(2):
        verdict = terminal._run_approval_guards("bash large.sh", "local", {}, force=force, required_review=review)
        assert verdict.approved_run and "user" in verdict.note
    assert len(calls) == 2


def test_review_binds_content_identity_and_cwd(supervised):
    script, _, check = supervised
    review = check()
    assert isinstance(review, guards.LifecycleScanReview)
    assert review.valid_for("bash large.sh", str(script.parent))
    assert not review.valid_for("bash large.sh", str(script.parent.parent))
    replacement = script.with_name("replacement.sh")
    replacement.write_bytes(script.read_bytes())
    replacement.replace(script)
    assert not review.valid_for("bash large.sh", str(script.parent))


@pytest.fixture
def terminal_env(supervised, monkeypatch):
    script, env, _check = supervised
    env.env = {}
    env.calls = []
    def execute(command, **kwargs):
        env.calls.append((command, kwargs))
        return {"output": "executed", "returncode": 0}
    env.execute = execute
    monkeypatch.setattr(terminal, "_get_env_config", lambda: {
        "env_type": "local", "cwd": str(script.parent), "timeout": 60, "lifetime_seconds": 3600})
    monkeypatch.setattr(terminal, "_acquire_env", lambda *a: env)
    monkeypatch.setattr(terminal, "_get_approval_callback", lambda: lambda *a, **kw: "once")
    return script, env


@pytest.mark.parametrize("force", [False, True])
def test_terminal_executes_only_after_one_shot_human_review(terminal_env, monkeypatch, force):
    _, env = terminal_env
    prompts = []
    monkeypatch.setattr(terminal, "_get_approval_callback", lambda: lambda *a, **kw: prompts.append(kw) or "once")
    for _ in range(2):
        result = json.loads(terminal.terminal_tool("bash large.sh", force=force))
        assert result["exit_code"] == 0, result
    assert len(env.calls) == len(prompts) == 2
    assert all(p["allow_session"] is False and p["allow_permanent"] is False for p in prompts)


@pytest.mark.parametrize("mutation", ["replace", "content", "cwd", "wrapper", "delete"])
@pytest.mark.parametrize("background", [False, True])
def test_mutation_while_awaiting_review_prevents_execution(terminal_env, monkeypatch, mutation, background):
    script, env = terminal_env
    wrapper = script.with_name("wrapper.sh")
    wrapper.write_text("bash large.sh\n")
    command = "bash wrapper.sh" if mutation == "wrapper" else "bash large.sh"
    spawned = []
    monkeypatch.setattr(terminal, "spawn_background_process", lambda **kw: spawned.append(kw) or "{}")
    def replace():
        new = script.with_name("new.sh")
        new.write_bytes(script.read_bytes())
        new.replace(script)
    def change_cwd():
        other = script.parent / "other"
        other.mkdir()
        monkeypatch.setattr(terminal, "get_session_cwd", lambda key: str(other))
    mutations = {
        "replace": replace,
        "content": lambda: script.write_text("# different\n" * 50),
        "delete": script.unlink,
        "wrapper": lambda: wrapper.write_text("hermes gateway stop\n"),
        "cwd": change_cwd,
    }
    def approve(*a, **kw):
        mutations[mutation]()
        return "once"
    monkeypatch.setattr(terminal, "_get_approval_callback", lambda: approve)
    result = json.loads(terminal.terminal_tool(command, background=background, force=True))
    assert result.get("status") == "blocked", result
    assert not env.calls and not spawned


def test_nonregular_replacement_is_rejected_before_open(supervised, monkeypatch):
    script, _, check = supervised
    review = check()
    script.unlink()
    script.mkdir()
    from pathlib import Path
    monkeypatch.setattr(Path, "open", lambda *a, **kw: pytest.fail("non-regular path must not be opened"))
    assert not review.valid_for("bash large.sh", str(script.parent))


@pytest.mark.parametrize("context", ["cron", "single_query", "unattended"])
def test_unattended_context_never_inherits_exception(supervised, monkeypatch, context):
    _, _, check = supervised
    review = check()
    monkeypatch.setattr(approval, "_presence", lambda cb=None: (cb, False, False, False))
    monkeypatch.setattr(approval_context, "_get_approval_mode", lambda: "off")
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    # Even configured approve-mode cannot replace an actual human answer.
    monkeypatch.setattr(approval_context, f"_get_{context}_approval_mode", lambda: "approve")
    result = approval.check_all_command_guards("bash large.sh", "local", required_review=review)
    assert result["approved"] is False
    assert "unattended" in result["message"]


def test_one_shot_review_does_not_authorize_retry_after_backend_error(terminal_env, monkeypatch):
    _, env = terminal_env
    def fail(command, **kw):
        env.calls.append(command)
        raise ConnectionError("uncertain execution")
    env.execute = fail
    monkeypatch.setattr(terminal.time, "sleep", lambda seconds: None)
    result = json.loads(terminal.terminal_tool("bash large.sh"))
    assert result.get("error")
    assert len(env.calls) == 1


@pytest.mark.parametrize("replacement", ["hermes gateway stop\n", "cd other; bash large.sh\n"])
def test_wrapper_change_between_discovery_and_hash_cannot_evade_scan(supervised, monkeypatch, replacement):
    script, _, check = supervised
    wrapper = script.with_name("wrapper.sh")
    wrapper.write_text("bash large.sh\n")
    original = guards._review_file_identity
    changed = False
    def mutate(path, **kw):
        nonlocal changed
        if not changed:
            changed = True
            wrapper.write_text(replacement)
        return original(path, **kw)
    monkeypatch.setattr(guards, "_review_file_identity", mutate)
    assert isinstance(check("bash wrapper.sh"), str)


@pytest.mark.parametrize("surface", ["cli", "stdin", "gateway", "ask", "plugin"])
@pytest.mark.parametrize("choice", ["once", "session", "always", "deny"])
def test_all_human_surfaces_keep_exception_once_only(supervised, monkeypatch, surface, choice):
    from tools import approval_prompt
    _, _, check = supervised
    review = check()
    seen = []
    monkeypatch.setattr(approval_context, "_get_approval_transport_config", lambda: ("builtin", None))
    monkeypatch.setattr(approval, "_smart_gate", lambda *a, **kw: pytest.fail("mandatory review cannot use smart approval"))
    monkeypatch.setattr(approval, "_persist_choice", lambda *a, **kw: pytest.fail("mandatory review cannot persist"))
    def callback(*args, **kwargs):
        seen.append(kwargs)
        return choice
    if surface == "plugin":
        monkeypatch.setattr(approval_context, "_get_approval_transport_config", lambda: ("phone", None))
        def present(request):
            seen.append({"allow_session": "session" in request.allowed_choices, "allow_permanent": "always" in request.allowed_choices})
            # Transport protocol itself rejects wider choices: exercise its genuine one-shot response.
            return request.respond("deny" if choice == "deny" else "once")
        monkeypatch.setattr(approval_prompt, "get_plugin_manager", lambda: SimpleNamespace(
            get_approval_transport=lambda name: SimpleNamespace(present=present)))
    elif surface in {"gateway", "ask"}:
        monkeypatch.setattr(approval, "_presence", lambda cb=None: (None, False, surface == "gateway", True))
        def notify(data):
            seen.append(data)
            assert approval.resolve_gateway_approval(approval.get_current_session_key(), choice) == 1
        monkeypatch.setattr(approval, "_gateway_notify_cb", lambda session: notify)
    elif surface == "stdin":
        monkeypatch.setattr(approval_prompt, "_read_choice", lambda *a: "o" if choice != "deny" else "n")
    for _ in range(2):
        result = approval.check_all_command_guards("bash large.sh", "local", required_review=review,
            approval_callback=callback if surface == "cli" else None)
        assert result["approved"] is (choice != "deny"), result
        assert not result.get("smart_approved") and not result.get("pre_approved")
    if surface != "stdin":
        assert len(seen) == 2
        assert all(not item["allow_session"] and not item["allow_permanent"] for item in seen)


@pytest.mark.parametrize("failure", ["timeout", "cancelled", "deny", "invalid"])
def test_cli_failures_do_not_execute(terminal_env, monkeypatch, failure):
    _, env = terminal_env
    monkeypatch.setattr(terminal, "_get_approval_callback", lambda: lambda *a, **kw: failure)
    result = json.loads(terminal.terminal_tool("bash large.sh", force=True))
    assert result.get("status") == "blocked", result
    assert not env.calls


def test_missing_async_bridge_is_not_a_force_replay_grant(terminal_env, monkeypatch):
    _, env = terminal_env
    monkeypatch.setattr(approval, "_presence", lambda cb=None: (None, False, False, True))
    monkeypatch.setattr(approval, "_gateway_notify_cb", lambda session: None)
    result = json.loads(terminal.terminal_tool("bash large.sh", force=True))
    assert result.get("status") == "blocked" and "bridge" in result["error"]
    assert not env.calls


def test_session_permanent_allowlist_and_prepared_batch_cannot_suppress_review(supervised, monkeypatch):
    from agent import terminal_approval_batch
    _, _, check = supervised
    review = check()
    monkeypatch.setattr(approval, "is_approved", lambda *a: True)
    monkeypatch.setattr(approval, "_command_matches_permanent_allowlist", lambda *a: True)
    monkeypatch.setattr(terminal_approval_batch, "consume_prepared_guard", lambda *a: pytest.fail("batch cannot authorize review"))
    prompts = []
    result = approval.check_all_command_guards("bash large.sh", "local", required_review=review,
        approval_callback=lambda *a, **kw: prompts.append(kw) or "deny")
    assert not result["approved"] and len(prompts) == 1


@pytest.mark.parametrize("hazard", ["root", "walk", "device", "cloud", "live_sqlite", "unreadable", "exception"])
def test_non_size_failures_stay_hard_blocks(supervised, monkeypatch, hazard):
    script, _, check = supervised
    small = script.with_name("small.sh")
    small.write_text("# harmless\n" * 8)
    def unreadable(*a, **kw):
        raise PermissionError("unreadable")
    def walk_failure(*a, **kw):
        raise RuntimeError("walk failed")
    setup = {
        "root": lambda: monkeypatch.setattr(lifecycle, "_MAX_LIFECYCLE_SCAN_BYTES", 4),
        "walk": lambda: monkeypatch.setattr(lifecycle, "_MAX_LIFECYCLE_SCAN_BYTES", 64),
        "device": lambda: None,
        "cloud": lambda: None,
        "live_sqlite": lambda: monkeypatch.setattr("hermes_cli.sqlite_safe_read.has_live_connection", lambda path: path == script),
        "unreadable": lambda: monkeypatch.setattr(guards, "_review_file_identity", unreadable),
        "exception": lambda: monkeypatch.setattr(lifecycle, "_iter_referenced_shell_scripts", walk_failure),
    }
    setup[hazard]()
    suffix = {"walk": "; bash small.sh", "device": "; bash /dev/zero",
              "cloud": "; bash ~/Library/CloudStorage/ops.sh"}.get(hazard, "")
    assert isinstance(check("bash large.sh" + suffix), str)


def test_remote_backends_do_not_gain_local_file_review(supervised):
    _, _, check = supervised
    assert isinstance(check(env_type="ssh"), str)


def test_hosted_scope_never_reads_host_review_files(supervised, monkeypatch):
    from tools.environments import sandbox_scope
    _, _, check = supervised
    monkeypatch.setattr(sandbox_scope, "hosted_scope", lambda: SimpleNamespace(tenant="hosted"))
    monkeypatch.setattr(guards, "_review_file_identity", lambda path: pytest.fail("hosted command must not read host files"))
    monkeypatch.setattr(lifecycle, "scan_gateway_lifecycle", lambda *a, **kw: pytest.fail("hosted command must not scan host"))
    assert check() is None


def test_registry_dispatch_runs_real_oversized_shell_only_after_review(terminal_env, monkeypatch):
    import subprocess
    from tools.registry import registry
    script, env = terminal_env
    monkeypatch.setattr(lifecycle, "_MAX_REFERENCED_SCRIPT_BYTES", 1024 * 1024)
    script.write_text("# opaque reviewed padding\n" * 50000 + "printf 'REVIEWED_RUN\\n'\n")
    prompts = []
    monkeypatch.setattr(terminal, "_get_approval_callback", lambda: lambda *a, **kw: prompts.append(kw) or "once")
    def execute(command, **kwargs):
        env.calls.append(command)
        proc = subprocess.run(["/bin/bash", "-c", command], cwd=kwargs["cwd"],
            env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=10, check=False)
        return {"returncode": proc.returncode, "output": proc.stdout + proc.stderr}
    env.execute = execute
    result = json.loads(registry.dispatch("terminal", {"command": "bash large.sh", "force": True}))
    assert result["exit_code"] == 0 and "REVIEWED_RUN" in result["output"], result
    assert len(prompts) == len(env.calls) == 1
    monkeypatch.setattr(terminal, "_get_approval_callback", lambda: lambda *a, **kw: "deny")
    denied = json.loads(registry.dispatch("terminal", {"command": "bash large.sh", "force": True}))
    assert denied["status"] == "blocked" and len(env.calls) == 1


@pytest.mark.parametrize("kind", ["stale", "always", "exception"])
def test_plugin_reply_must_be_current_request_and_once_scope(supervised, monkeypatch, kind):
    from tools import approval_prompt
    _, _, check = supervised
    review = check()
    stale = []
    def present(request):
        if not stale:
            stale.append(request.respond("once"))
            return stale[0]
        if kind == "exception":
            raise RuntimeError("transport failed")
        return stale[0] if kind == "stale" else request.respond("always")
    monkeypatch.setattr(approval_context, "_get_approval_transport_config", lambda: ("phone", None))
    monkeypatch.setattr(approval_prompt, "get_plugin_manager", lambda: SimpleNamespace(
        get_approval_transport=lambda name: SimpleNamespace(present=present)))
    assert approval.check_all_command_guards("bash large.sh", "local", required_review=review)["approved"]
    assert not approval.check_all_command_guards("bash large.sh", "local", required_review=review)["approved"]


@pytest.mark.parametrize("context", ["cron", "single_query", "unattended_platform"])
def test_real_presence_disables_inherited_interactive_callback(supervised, monkeypatch, context):
    _, _, check = supervised
    review = check()
    monkeypatch.setattr(approval, f"_is_{context}_approval_context", lambda: True)
    monkeypatch.setenv("HERMES_EXEC_ASK", "1")
    monkeypatch.setattr(approval, "_get_session_platform", lambda: "webhook")
    result = approval.check_all_command_guards("bash large.sh", "local", required_review=review,
        approval_callback=lambda *a, **kw: pytest.fail("unattended context cannot prompt"))
    assert not result["approved"]


def test_review_hashing_has_aggregate_budget(supervised):
    script, _, check = supervised
    second = script.with_name("second.sh")
    # Sparse regular files: fail without reading gigabytes or feeding them to shlex.
    for path in (script, second):
        with path.open("wb") as source:
            source.write(b"#")
            source.truncate(33 * 1024 * 1024)
    assert isinstance(check("bash large.sh; bash second.sh"), str)


@pytest.mark.parametrize("where", ["command", "wrapper"])
def test_known_directory_change_cannot_bind_wrong_script(supervised, where):
    script, _, check = supervised
    other = script.parent / "other"
    other.mkdir()
    (other / "large.sh").write_text("# different opaque script\n" * 20)
    command = "cd other; bash large.sh"
    if where == "wrapper":
        wrapper = script.with_name("wrapper.sh")
        wrapper.write_text(command + "\n")
        command = "bash wrapper.sh"
    assert isinstance(check(command), str)
