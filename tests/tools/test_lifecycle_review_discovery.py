"""Bind review to shell execution paths and never defer scanner I/O failures."""
import os
import subprocess
from types import SimpleNamespace

import pytest

from cron import lifecycle_guard as lifecycle
from tools import terminal_tool as terminal
from tools import terminal_tool_guards as guards


@pytest.fixture
def check(tmp_path, monkeypatch):
    monkeypatch.setattr("tools.process_registry._is_supervised_gateway_process", lambda: True)
    monkeypatch.setattr(terminal, "get_session_cwd", lambda key: None)

    def guard(command):
        return guards.gateway_lifecycle_block(
            command=command, env=SimpleNamespace(cwd=str(tmp_path)), env_type="local",
            cwd=str(tmp_path), workdir=None, session_key="discovery-test")

    return guard


def oversized(path):
    path.write_text("# opaque padding\n" * 70000)


@pytest.mark.platforms("posix")
@pytest.mark.parametrize("actual_oversized", [False, True])
@pytest.mark.parametrize("invocation", ["bash wrappers/wrapper.sh", ". wrappers/wrapper.sh", "./wrappers/wrapper.sh"])
def test_wrapper_references_use_inherited_shell_cwd(tmp_path, check, actual_oversized, invocation):
    wrappers = tmp_path / "wrappers"
    wrappers.mkdir()
    wrapper = wrappers / "wrapper.sh"
    wrapper.write_text("#!/bin/sh\nbash large.sh\n")
    wrapper.chmod(0o700)
    decoy = wrappers / "large.sh"
    oversized(decoy)
    actual = tmp_path / "large.sh"
    actual.write_text("printf 'ACTUAL_BEFORE\\n'\n")
    if actual_oversized:
        oversized(actual)

    review = check(invocation)
    if actual_oversized:
        assert isinstance(review, guards.LifecycleScanReview), review
        assert {path for path, _ in review.files} == {str(wrapper), str(actual)}
        assert review.valid_for(invocation, str(tmp_path))
    else:
        # An unrelated oversized sibling cannot create an exception for a fully scanned command.
        assert review is None
    actual.write_text("printf 'ACTUAL_CHANGED_AFTER_REVIEW\\n'\n")
    proc = subprocess.run(
        ["/bin/bash", "-c", invocation], cwd=tmp_path, env={"PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=5, check=False)
    assert proc.returncode == 0 and proc.stdout.strip() == "ACTUAL_CHANGED_AFTER_REVIEW"
    if actual_oversized:
        assert not review.valid_for(invocation, str(tmp_path))


@pytest.mark.parametrize("operation,target_oversized", [
    (operation, oversized) for operation in ("open", "fstat", "read", "remainder", "close")
    for oversized in (False, True) if not (operation == "remainder" and oversized)
])
def test_scanner_io_failure_cannot_be_deferred_as_file_size(
    tmp_path, monkeypatch, check, operation, target_oversized,
):
    oversized(tmp_path / "large.sh")
    target = tmp_path / "target.sh"
    # NUL-bearing text bypassed the legacy terminal fallback; bash still treats it as a script.
    target.write_bytes(b"# ordinary executable reference\x00\nprintf OK\\n\n")
    if target_oversized:
        oversized(target)
    inode = target.stat().st_ino
    real_fstat = os.fstat
    calls = []
    syscall = "read" if operation == "remainder" else operation
    original = getattr(os, syscall)

    def fail_target(*args, **kwargs):
        matches = str(args[0]) == str(target) if syscall == "open" else real_fstat(args[0]).st_ino == inode
        if matches:
            calls.append(args)
            if operation != "remainder" or len(calls) > 1:
                # Close the actual descriptor even when simulating close failure.
                if syscall == "close":
                    original(*args, **kwargs)
                raise OSError("injected scanner I/O failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(lifecycle.os, syscall, fail_target)
    command = "bash large.sh; bash target.sh"
    scan = lifecycle.LifecycleReviewScan()
    unsafe, refusal = lifecycle.scan_gateway_lifecycle(command, cwd=str(tmp_path), review=scan)
    assert calls
    assert unsafe and refusal and getattr(refusal, "reason", None) != "file_size"
    blocked = check(command)
    assert isinstance(blocked, str), blocked


def test_compiled_binary_is_not_a_scanner_io_failure(tmp_path, check):
    oversized(tmp_path / "large.sh")
    binary = tmp_path / "compiled"
    binary.write_bytes(b"\x7fELF\x00compiled binary\x00")
    review = check("bash large.sh; ./compiled")
    assert isinstance(review, guards.LifecycleScanReview), review
    assert review.valid_for("bash large.sh; ./compiled", str(tmp_path))
