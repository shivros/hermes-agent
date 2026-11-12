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


def wrapper(tmp_path, body):
    wrappers = tmp_path / "wrappers"
    wrappers.mkdir()
    script = wrappers / "wrapper.sh"
    script.write_text(body)
    script.chmod(0o700)
    return script


@pytest.mark.platforms("posix")
@pytest.mark.parametrize("change", ['cd "$(dirname "$0")"', 'cd "$(dirname "${BASH_SOURCE[0]}")"', 'cd "${0%/*}"'])
@pytest.mark.parametrize("sibling", ["inner.sh", "./inner.sh"])
def test_wrapper_directory_change_scans_its_own_directory(tmp_path, check, change, sibling):
    """`cd "$(dirname "$0")"` moves a wrapper's relative references to its own directory. The
    walk must read them there (upstream's model) and from the inherited cwd (a shell with no cd):
    scanning only one location hid a restart behind the other."""
    script = wrapper(tmp_path, f"{change} && bash {sibling}\n")
    (script.parent / "inner.sh").write_text("hermes gateway restart\n")
    (tmp_path / "inner.sh").write_text("printf 'RAN_FROM_CWD\n'\n")
    command = "bash wrappers/wrapper.sh"
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(tmp_path)) == (True, None)
    blocked = check(command)
    assert isinstance(blocked, str) and "Blocked" in blocked, blocked
    # The verdict matches the shell: the wrapper-directory sibling is the one that really runs.
    (script.parent / "inner.sh").write_text("printf 'RAN_FROM_WRAPPER_DIR\n'\n")
    proc = subprocess.run(["/bin/bash", "wrappers/wrapper.sh"], cwd=tmp_path,
                          env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=5, check=False)
    assert proc.returncode == 0 and proc.stdout.strip() == "RAN_FROM_WRAPPER_DIR", proc


@pytest.mark.platforms("posix")
def test_wrapper_without_directory_change_keeps_the_inherited_cwd(tmp_path, check):
    """No directory change: a wrapper does not chdir to its own directory, so its relative
    references are read from the inherited cwd only. An unused same-named restart script beside
    the wrapper is not executed and must not block the benign command that is."""
    script = wrapper(tmp_path, "bash inner.sh\n")
    (script.parent / "inner.sh").write_text("hermes gateway restart\n")
    (tmp_path / "inner.sh").write_text("printf 'REAL_TARGET\n'\n")
    command = "bash wrappers/wrapper.sh"
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(tmp_path)) == (False, None)
    assert check(command) is None
    proc = subprocess.run(["/bin/bash", "wrappers/wrapper.sh"], cwd=tmp_path,
                          env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=5, check=False)
    assert proc.returncode == 0 and proc.stdout.strip() == "REAL_TARGET", proc
    (tmp_path / "inner.sh").write_text("hermes gateway restart\n")
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(tmp_path)) == (True, None)
    assert isinstance(check(command), str)


@pytest.mark.platforms("posix")
def test_wrapper_directory_change_never_gets_a_review(tmp_path, check):
    """A directory change makes file identities ambiguous behind it: refuse instead of binding
    whichever location the walk happened to read."""
    script = wrapper(tmp_path, 'cd "$(dirname "$0")" && bash large.sh\n')
    oversized(script.parent / "large.sh")
    blocked = check("bash wrappers/wrapper.sh")
    assert isinstance(blocked, str) and "Blocked" in blocked, blocked


@pytest.mark.platforms("posix")
@pytest.mark.parametrize("source_form", ['source "$(dirname "$0")/env.sh"', '. "$(dirname "$0")/env.sh"'])
def test_sourced_directory_change_scans_the_wrappers_own_directory(tmp_path, check, source_form):
    """The directory change may live in a file the wrapper sources. The sourced helper's
    `cd "$(dirname "$0")"` moves the shell (sourcing keeps the wrapper's `$0`) before the
    wrapper's next relative reference, which then resolves from the wrapper's directory although
    the wrapper's own text has no `cd`."""
    script = wrapper(tmp_path, f"{source_form} && bash inner.sh\n")
    (script.parent / "env.sh").write_text('cd "$(dirname "$0")"\n')
    (script.parent / "inner.sh").write_text("hermes gateway restart\n")
    (tmp_path / "inner.sh").write_text("printf 'RAN_FROM_CWD'\n")
    command = "bash wrappers/wrapper.sh"
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(tmp_path)) == (True, None)
    assert isinstance(check(command), str)
    # The verdict matches the shell: the wrapper-directory sibling is the one that really runs.
    (script.parent / "inner.sh").write_text("printf 'RAN_FROM_WRAPPER_DIR'\n")
    proc = subprocess.run(["/bin/bash", "wrappers/wrapper.sh"], cwd=tmp_path,
                          env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=5, check=False)
    assert proc.returncode == 0 and proc.stdout.strip() == "RAN_FROM_WRAPPER_DIR", proc


@pytest.mark.platforms("posix")
def test_large_wrapper_is_not_charged_twice_for_its_second_scan(tmp_path, check):
    """The wrapper's own text was charged on the inherited-cwd scan. Charging it again for the
    scan from its own directory makes a large wrapper whose only `cd` is prose fail closed on the
    walk budget where one scan passes."""
    padding = ("# cd is only a word in this comment line " + "y" * 15 + "\n") * 12000  # 600 KiB
    script = wrapper(tmp_path, "#!/bin/sh\n" + padding + 'cd "$(dirname "$0")" && bash inner.sh\n')
    (script.parent / "inner.sh").write_text("printf 'RAN_FROM_WRAPPER_DIR'\n")
    command = "bash wrappers/wrapper.sh"
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(tmp_path)) == (False, None)
    (script.parent / "inner.sh").write_text("hermes gateway restart\n")
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(tmp_path)) == (True, None)


@pytest.mark.platforms("posix")
def test_same_directory_spelled_differently_is_scanned_once(tmp_path, check, monkeypatch):
    """cwd and the wrapper's directory are one directory spelled differently: the scan from the
    wrapper's own directory would repeat the inherited-cwd scan for nothing."""
    script = wrapper(tmp_path, 'cd "$(dirname "$0")" && bash inner.sh\n')
    (script.parent / "inner.sh").write_text("printf 'OK'\n")
    scanned = []
    real = lifecycle._contains_unsafe_gateway_action

    def spy(command, *, cwd, **kwargs):
        scanned.append(cwd)
        return real(command, cwd=cwd, **kwargs)

    monkeypatch.setattr(lifecycle, "_contains_unsafe_gateway_action", spy)
    assert lifecycle.scan_gateway_lifecycle("bash wrapper.sh", cwd=str(script.parent) + "/") == (False, None)
    assert len(scanned) == 3, scanned  # the command, the wrapper text, the nested script


@pytest.mark.platforms("posix")
@pytest.mark.parametrize("helper_reference", ["absolute path", "directory-relative path"])
def test_own_directory_pass_rereads_a_helper_read_from_the_inherited_cwd(
    tmp_path, check, monkeypatch, helper_reference,
):
    """A cd-wrapper reaches its helper by a reference that resolves the same way from both
    directories. The inherited-cwd scan reads the helper there and finds nothing; the scan from
    the wrapper's directory must read it AGAIN, because the helper's own relative reference then
    resolves from the directory the cd moved the shell to. "Already read" is per directory: keyed
    by path alone it skipped the helper and missed the restart beside it (upstream blocks this)."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    helper = scripts / "helper.sh"
    helper.write_text("bash inner.sh\n")
    (scripts / "inner.sh").write_text("hermes gateway restart\n")
    (work / "inner.sh").write_text("printf 'RAN_FROM_CWD'\n")
    reference = str(helper) if helper_reference == "absolute path" else "../scripts/helper.sh"
    (scripts / "wrapper.sh").write_text(f'cd "$(dirname "$0")" && bash {reference}\n')
    reads = []
    real = lifecycle._read_referenced_script

    def spy(path, **kwargs):
        reads.append(os.path.realpath(str(path)))
        return real(path, **kwargs)

    monkeypatch.setattr(lifecycle, "_read_referenced_script", spy)
    command = "bash ../scripts/wrapper.sh"
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(work)) == (True, None)
    # once per directory the wrapper's shell occupies
    assert reads.count(str(helper)) == 2, reads
    blocked = guards.gateway_lifecycle_block(
        command=command, env=SimpleNamespace(cwd=str(work)), env_type="local",
        cwd=str(work), workdir=None, session_key="discovery-test")
    assert isinstance(blocked, str) and "Blocked" in blocked, blocked
    # The verdict matches the shell: the restart sibling beside the helper is the one that runs.
    (scripts / "inner.sh").write_text("printf 'RAN_FROM_WRAPPER_DIR'\n")
    proc = subprocess.run(["/bin/bash", "../scripts/wrapper.sh"], cwd=work,
                          env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=5, check=False)
    assert proc.returncode == 0 and proc.stdout.strip() == "RAN_FROM_WRAPPER_DIR", proc


@pytest.mark.platforms("posix")
@pytest.mark.parametrize("written", ["the cd-wrapper itself", "a helper behind a cd-wrapper"])
def test_heredoc_written_script_is_scanned_from_its_own_directory(tmp_path, check, written):
    """A body the command writes and then runs IS that script's text. Once it runs as
    `<scripts>/P.sh`, its `cd "$(dirname "$0")"` moves the shell to <scripts>/ exactly like a
    script read from disk, so the body gets the same scan from its own directory."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "inner.sh").write_text("hermes gateway restart\n")
    if written == "the cd-wrapper itself":
        command = (f"cat > {scripts}/P.sh <<'EOF'\n"
                   'cd "$(dirname "$0")" && bash inner.sh\n'
                   f"EOF\nbash {scripts}/P.sh")
    else:
        (scripts / "wrapper.sh").write_text(
            f'#!/bin/sh\ncd "$(dirname "$0")" && bash {scripts}/gen.sh\n')
        command = (f"cat > {scripts}/gen.sh <<'EOF'\nbash inner.sh\nEOF\n"
                   f"bash {scripts}/wrapper.sh")
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(tmp_path)) == (True, None)
    assert isinstance(check(command), str)
    # The verdict matches the shell: the written script really runs the restart sibling.
    (scripts / "inner.sh").write_text("printf 'RAN_FROM_SCRIPT_DIR'\n")
    proc = subprocess.run(["/bin/bash", "-c", command], cwd=tmp_path,
                          env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=5, check=False)
    assert proc.returncode == 0 and proc.stdout.strip() == "RAN_FROM_SCRIPT_DIR", proc


@pytest.mark.platforms("posix")
@pytest.mark.parametrize("helper_refusal", ["oversized file", "starved by the walk budget"])
def test_mention_scan_never_covers_a_later_executed_encounter(tmp_path, check, monkeypatch, helper_refusal):
    """X.sh only MENTIONS A.sh (an inert heredoc); the command then RUNS A.sh, which runs a helper
    the scanner cannot read. Read as a mention, A.sh marked its node "scanned", so the executed
    encounter was skipped and the unreadable helper ran without its fail-closed verdict (upstream
    refuses A.sh whenever it is executed alone)."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    if helper_refusal == "oversized file":
        oversized(scripts / "big.sh")
    else:
        monkeypatch.setattr(lifecycle, "_MAX_LIFECYCLE_SCAN_BYTES", 4096)
        (scripts / "big.sh").write_text("".join("# " + "y" * 103 + "\n" for _ in range(20)))
        (scripts / "X.sh").write_text("".join("# " + "x" * 103 + "\n" for _ in range(28)))
    (scripts / "A.sh").write_text(f"bash {scripts}/big.sh\n")
    with (scripts / "X.sh").open("a") as handle:
        handle.write(f"cat <<'EOF'\nbash {scripts}/A.sh\nEOF\n")
    command = f"bash {scripts}/X.sh; bash {scripts}/A.sh"
    # The executed walk reaches the helper and refuses it for the reason it cannot be read.
    refused = lifecycle.scan_gateway_lifecycle(command, cwd=str(work))
    assert refused[0] is True and isinstance(refused[1], str), refused
    review = check(command)
    if helper_refusal == "oversized file":
        # The per-file cap is reviewable: the human is shown the helper that really runs.
        assert isinstance(review, guards.LifecycleScanReview), review
        assert str(scripts / "big.sh") in {path for path, _ in review.files}
        assert review.valid_for(command, str(tmp_path))  # `check` scans from tmp_path
    else:
        # A budget starvation is not a size refusal; nothing is offered for approval.
        assert isinstance(review, str)
    # Control: the same encounter order with a readable helper is allowed.
    (scripts / "big.sh").write_text("printf ok\n")
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(work)) == (False, None)
    assert check(command) is None


@pytest.mark.platforms("posix")
def test_written_body_starved_as_a_mention_is_scanned_when_executed(tmp_path, check, monkeypatch):
    """A1.sh fills the walk budget, then merely MENTIONS P.sh. P.sh's heredoc body is scanned as
    that mention and its `bash inner.sh` cannot be read. "Scanned" for the mention covered the
    executed `bash P.sh` too, so the body never got an executed scan (minor 1, written side)."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    monkeypatch.setattr(lifecycle, "_MAX_LIFECYCLE_SCAN_BYTES", 4096)
    (tmp_path / "inner.sh").write_text("".join("# " + "i" * 103 + "\n" for _ in range(14)))
    (scripts / "A1.sh").write_text(
        "".join("# " + "p" * 103 + "\n" for _ in range(28))
        + f"cat <<'EOF2'\nbash {scripts}/P.sh\nEOF2\n"
    )
    command = (f"cat > {scripts}/P.sh <<'EOF'\nbash inner.sh\nEOF\n"
               f"bash {scripts}/A1.sh; bash {scripts}/P.sh")
    cwd = str(tmp_path)
    # The executed `bash P.sh` gets its own scan of the body and refuses the helper it cannot read.
    refused = lifecycle.scan_gateway_lifecycle(command, cwd=cwd)
    assert refused[0] is True and isinstance(refused[1], str), refused
    assert isinstance(check(command), str)
    (tmp_path / "inner.sh").write_text("printf ok\n")
    assert lifecycle.scan_gateway_lifecycle(command, cwd=cwd) == (False, None)
    assert check(command) is None


@pytest.mark.platforms("posix")
def test_unusable_cwd_spelling_does_not_hide_the_wrappers_own_directory(tmp_path):
    """`<scripts>/missing/..` names <scripts> but nothing can be read through it. "Same directory
    under another spelling" dropped the wrapper's own-directory scan, so the wrapper's sibling was
    never read (upstream, which always scans from the script's directory, blocks this)."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "w.sh").write_text('cd "$(dirname "$0")"\nbash sibling.sh\n')
    (scripts / "sibling.sh").write_text("hermes gateway restart\n")
    unusable = str(scripts / "missing" / "..")
    assert lifecycle.scan_gateway_lifecycle(f"bash {scripts}/w.sh", cwd=unusable) == (True, None)
    # The unreadable relative spelling must not mark the wrapper as scanned either.
    assert lifecycle.scan_gateway_lifecycle(
        f"bash w.sh; bash {scripts}/w.sh", cwd=unusable) == (True, None)
    (scripts / "sibling.sh").write_text("printf ok\n")
    assert lifecycle.scan_gateway_lifecycle(f"bash {scripts}/w.sh", cwd=unusable) == (False, None)


@pytest.mark.platforms("posix")
def test_autocd_counts_as_a_directory_change(tmp_path, check):
    """`autocd` turns a bare directory name into a cd, so there is no cd token to see. zsh honours
    it in scripts (non-interactive bash, this host's shell, ignores it), so the wrapper below can
    move into its own directory by name and run a sibling from there. The scan from the wrapper's
    own directory has to happen, and a review must not pretend to have bound a reference the shell
    resolves only after that move. The rule is over-inclusive like the rest of
    _DIRECTORY_CHANGE_RE: a false positive costs one more bounded scan."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (tmp_path / "big.sh").write_text("printf 'RAN_FROM_CWD'\n")
    (scripts / "big.sh").write_text("hermes gateway restart\n")
    (scripts / "w.sh").write_text("shopt -s autocd\nscripts\nbash big.sh\n")
    assert lifecycle._changes_directory((scripts / "w.sh").read_text())
    command = "bash scripts/w.sh"
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(tmp_path)) == (True, None)
    assert isinstance(check(command), str)
    # Review mode: the sibling the moved shell would run cannot be scanned. Only the harmless
    # same-named file in the inherited cwd is readable, so nothing is offered for approval.
    oversized(scripts / "big.sh")
    blocked = check(command)
    assert isinstance(blocked, str) and "could not bind" in blocked, blocked


@pytest.mark.platforms("posix")
@pytest.mark.parametrize(
    ("command", "paths"),
    [
        ("bash e.sh; bash e.sh", 1),
        ("bash missing.sh; bash missing.sh; cat missing.sh", 1),
        ("cat e.sh; cat missing.sh; bash missing.sh; bash e.sh", 2),
        ("bash e.sh; bash missing.sh; bash e.sh; bash missing.sh", 2),
    ],
)
def test_absent_or_empty_script_is_charged_once(tmp_path, monkeypatch, command, paths):
    """A read that finds nothing (absent or empty) established there is nothing to scan at any
    strictness, so it settles later mentions AND executions: the same path budget upstream
    allows. Only a refused read (oversized, device, ...) is left owing a verdict once executed."""
    (tmp_path / "e.sh").write_text("")
    monkeypatch.setattr(lifecycle, "_MAX_LIFECYCLE_SCAN_PATHS", paths)
    assert lifecycle.scan_gateway_lifecycle(command, cwd=str(tmp_path)) == (False, None)
