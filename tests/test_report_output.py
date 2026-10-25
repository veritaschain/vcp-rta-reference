"""No-clobber report publication; all inputs and fault injections are local tests."""
from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading

import pytest

DIRECTORY = Path(__file__).resolve().parents[1] / "tools" / "verifier"
sys.path.insert(0, str(DIRECTORY))
import vcp_verifier as legacy

CLIS = ("vcp_verifier.py", "verify_attested_batch.py")


def run_cli(script, events, output=None, extra=(), *, json_output=True):
    command = [sys.executable, str(DIRECTORY / script), str(events)]
    if json_output:
        command += ["--json"]
    if output is not None:
        command += ["--output", str(output)]
    return subprocess.run(command + list(extra), capture_output=True, text=True, timeout=10)


def event_file(tmp_path):
    # Deliberately incomplete, synthetic input. The verdict must remain INVALID.
    path = tmp_path / "events.jsonl"
    path.write_text('{}\n', encoding="utf-8")
    return path


@pytest.mark.parametrize("script", CLIS)
@pytest.mark.parametrize("alias", ["same", "relative", "symlink", "hardlink"])
def test_input_alias_never_overwritten(tmp_path, script, alias):
    events = event_file(tmp_path)
    before = events.read_bytes()
    output = events
    if alias == "relative":
        (tmp_path / "child").mkdir()
        output = tmp_path / "child" / ".." / events.name
    elif alias == "symlink":
        output = tmp_path / "report.json"
        output.symlink_to(events)
    elif alias == "hardlink":
        output = tmp_path / "report.json"
        os.link(events, output)
    result = run_cli(script, events, output)
    assert result.returncode == 3
    assert "Cannot write report" in result.stderr
    assert json.loads(result.stdout)["status"] == legacy.INVALID
    assert events.read_bytes() == before
    assert output.read_bytes() == before
    assert not list(tmp_path.glob(".vcp-report-*.tmp"))


@pytest.mark.parametrize("script", CLIS)
@pytest.mark.parametrize("kind", ["file", "empty_file", "directory", "dangling_symlink"])
def test_existing_destinations_rejected(tmp_path, script, kind):
    events = event_file(tmp_path)
    output = tmp_path / "report.json"
    target = tmp_path / "absent.json"
    if kind == "file":
        output.write_bytes(b"OLD REPORT\n")
    elif kind == "empty_file":
        output.touch()
    elif kind == "directory":
        output.mkdir()
    else:
        output.symlink_to(target)
    before = output.read_bytes() if kind in ("file", "empty_file") else None
    result = run_cli(script, events, output)
    assert result.returncode == 3
    if before is not None:
        assert output.read_bytes() == before
    elif kind == "directory":
        assert output.is_dir() and not list(output.iterdir())
    else:
        assert output.is_symlink() and not target.exists()
    assert events.read_bytes() == b'{}\n'
    assert not list(tmp_path.glob(".vcp-report-*.tmp"))


INPUT_OPTIONS = [(script, flag) for script in CLIS for flag in
                 (("--security-object", "--public-key") if script == "vcp_verifier.py" else
                  ("--security-object", "--public-key", "--attestation", "--attestor-key",
                   "--tsa-response", "--tsa-ca-file", "--tsa-untrusted"))]


@pytest.mark.parametrize("script,flag", INPUT_OPTIONS)
def test_optional_input_not_overwritten_even_when_unusable(tmp_path, script, flag):
    events = event_file(tmp_path)
    protected = tmp_path / "optional-input.bin"
    protected.write_bytes(b"SYNTHETIC UNUSABLE INPUT\n")
    before = protected.read_bytes()
    result = run_cli(script, events, protected, (flag, str(protected)))
    assert result.returncode == 3
    assert protected.read_bytes() == before
    assert json.loads(result.stdout)["status"] == legacy.INVALID


@pytest.mark.parametrize("script,flag", INPUT_OPTIONS)
def test_missing_optional_input_not_created_as_output(tmp_path, script, flag):
    events = event_file(tmp_path)
    missing = tmp_path / "missing-input.bin"
    result = run_cli(script, events, missing, (flag, str(missing)))
    assert result.returncode == 3
    assert not missing.exists()
    assert json.loads(result.stdout)["status"] == legacy.INVALID


@pytest.mark.parametrize("script", CLIS)
@pytest.mark.parametrize("json_output", [True, False])
def test_new_report_exact_bytes_and_private_permissions(tmp_path, script, json_output):
    events = event_file(tmp_path)
    output = tmp_path / "new-report.json"
    result = run_cli(script, events, output, json_output=json_output)
    assert result.returncode == 1
    assert output.read_bytes() == result.stdout.encode("utf-8")
    assert events.read_bytes() == b'{}\n'
    assert not list(tmp_path.glob(".vcp-report-*.tmp"))
    if os.name == "posix":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600


@pytest.mark.parametrize("script", CLIS)
def test_second_run_preserves_existing_report(tmp_path, script):
    events = event_file(tmp_path)
    output = tmp_path / "report.json"
    assert run_cli(script, events, output).returncode == 1
    before = hashlib.sha256(output.read_bytes()).digest()
    assert run_cli(script, events, output).returncode == 3
    assert hashlib.sha256(output.read_bytes()).digest() == before


@pytest.mark.parametrize("script", CLIS)
def test_missing_output_parent_is_not_created(tmp_path, script):
    events = event_file(tmp_path)
    output = tmp_path / "missing-parent" / "report.json"
    result = run_cli(script, events, output)
    assert result.returncode == 3
    assert not output.parent.exists()
    assert events.read_bytes() == b'{}\n'


def test_unicode_report_bytes(tmp_path):
    output = tmp_path / "日本語.json"
    text = '{"note":"検証結果"}\n'
    legacy.write_new_report(str(output), text)
    assert output.read_bytes() == text.encode("utf-8")


def test_encoding_failure_leaves_no_output(tmp_path):
    with pytest.raises(UnicodeEncodeError):
        legacy.write_new_report(str(tmp_path / "report.json"), "\ud800")
    assert not list(tmp_path.iterdir())


def test_fsync_failure_does_not_publish_partial_report(tmp_path, monkeypatch):
    def fail(_):
        raise OSError(errno.ENOSPC, "synthetic disk-full failure")
    monkeypatch.setattr(legacy.os, "fsync", fail)
    with pytest.raises(OSError):
        legacy.write_new_report(str(tmp_path / "report.json"), "complete report\n")
    assert not list(tmp_path.iterdir())


def test_unsupported_hardlinks_never_fall_back_to_overwrite(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError(errno.EOPNOTSUPP, "synthetic unsupported link")
    monkeypatch.setattr(legacy.os, "link", fail)
    with pytest.raises(OSError):
        legacy.write_new_report(str(tmp_path / "report.json"), "complete report\n")
    assert not list(tmp_path.iterdir())


def test_destination_created_during_publication_is_preserved(tmp_path, monkeypatch):
    target = tmp_path / "report.json"
    original_link = legacy.os.link
    def racing_link(src, dst, **kwargs):
        # Interleave after the preliminary path check, before exclusive publish.
        Path(dst).write_bytes(b"OTHER WRITER\n")
        return original_link(src, dst, **kwargs)
    monkeypatch.setattr(legacy.os, "link", racing_link)
    with pytest.raises(FileExistsError):
        legacy.write_new_report(str(target), "new report\n")
    assert target.read_bytes() == b"OTHER WRITER\n"
    assert list(tmp_path.iterdir()) == [target]


def test_symlink_created_during_publication_is_not_followed(tmp_path, monkeypatch):
    victim = tmp_path / "synthetic-input"
    victim.write_bytes(b"KEEP\n")
    output = tmp_path / "report.json"
    original_link = legacy.os.link
    def racing_link(src, dst, **kwargs):
        Path(dst).symlink_to(victim)
        return original_link(src, dst, **kwargs)
    monkeypatch.setattr(legacy.os, "link", racing_link)
    with pytest.raises(FileExistsError):
        legacy.write_new_report(str(output), "new report\n")
    assert output.is_symlink()
    assert victim.read_bytes() == b"KEEP\n"
    assert not list(tmp_path.glob(".vcp-report-*.tmp"))


def test_concurrent_writers_publish_one_complete_report(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    barrier = threading.Barrier(2)
    original_link = legacy.os.link
    def synchronized_link(src, dst, **kwargs):
        barrier.wait(timeout=10)
        return original_link(src, dst, **kwargs)
    monkeypatch.setattr(legacy.os, "link", synchronized_link)
    payloads = ["A" * 10000 + "\n", "B" * 10000 + "\n"]
    def publish(text):
        try:
            legacy.write_new_report(str(output), text)
            return "published"
        except FileExistsError:
            return "refused"
    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(publish, payloads))
    assert sorted(outcomes) == ["published", "refused"]
    assert output.read_text() in payloads
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.parametrize("script", CLIS)
def test_stdout_only_still_reports_same_verdict(tmp_path, script):
    events = event_file(tmp_path)
    result = run_cli(script, events)
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == legacy.INVALID
    assert list(tmp_path.iterdir()) == [events]
