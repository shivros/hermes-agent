"""Tests for the optional profile-local TTS text normalizer."""

from tools.tts_tool import _apply_user_tts_normalizer


def test_uses_profile_local_tts_normalizer(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    scripts = home / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "tts_normalize.py").write_text(
        "def tts_normalize(text):\n    return 'CUSTOM:' + text\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))

    assert _apply_user_tts_normalizer("hello") == "CUSTOM:hello"


def test_missing_profile_local_tts_normalizer_is_a_noop(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))

    assert _apply_user_tts_normalizer("hello") == "hello"
