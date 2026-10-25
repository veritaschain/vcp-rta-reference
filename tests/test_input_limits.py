"""Bounded file/JSON ingestion. Synthetic local inputs, not conformance tests."""
import base64
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

DIRECTORY = Path(__file__).resolve().parents[1] / "tools" / "verifier"
sys.path.insert(0, str(DIRECTORY))
import vcp_verifier as v

CLIS = [pytest.param("vcp_verifier.py", id="default"),
        pytest.param("verify_attested_batch.py", id="supplemental")]
LOADERS = [v.load_events, v.load_security_object, v.load_public_key]


@pytest.mark.parametrize("token", ["1e9999", "-1e9999", "1.0e9999", "NaN", "Infinity", "-Infinity"])
def test_nonfinite_numbers_rejected_in_unused_fields(token):
    with pytest.raises(ValueError):
        v._json('{"unused":' + token + '}')


@pytest.mark.parametrize("token", ["0.0", "-0.0", "1e-300", "1.7976931348623157e308"])
def test_finite_float_encoding_unchanged(token):
    actual, expected = v._json(token), json.loads(token)
    assert actual == expected
    assert math.copysign(1, actual) == math.copysign(1, expected)
    assert json.dumps(actual) == json.dumps(expected)


@pytest.mark.parametrize("number", [2**53+1, 1763638705482204928, -(2**63), 10**100])
def test_large_integer_digits_not_converted_to_float(number):
    assert type(v._json(str(number))) is int
    assert v._json(str(number)) == number


def test_duplicate_keys_still_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        v._json('{"a":1,"a":2}')


@pytest.mark.parametrize("kind", ["list", "object"])
def test_nesting_limit_exact_and_plus_one(kind):
    wrap = lambda n: ('[' * n + '0' + ']' * n if kind == "list" else
                      '{"x":' * n + '0' + '}' * n)
    assert v._json(wrap(v.MAX_JSON_DEPTH)) == json.loads(wrap(v.MAX_JSON_DEPTH))
    with pytest.raises(ValueError, match="nesting"):
        v._json(wrap(v.MAX_JSON_DEPTH + 1))


@pytest.mark.parametrize("text", ['[{}]' * 100, '\\"[{x}]', '\\\\"' * 100, '日本語\u2028\u2029'])
def test_brackets_and_escapes_in_strings_not_counted_as_depth(text):
    encoded = json.dumps({"text": text}, ensure_ascii=False)
    assert v._json(encoded) == {"text": text}


def test_json_byte_limit_is_utf8_not_characters(monkeypatch):
    monkeypatch.setattr(v, "MAX_JSON_BYTES", 8)
    assert v._json('"ああ"') == 'ああ'  # Eight UTF-8 bytes.
    with pytest.raises(ValueError, match="byte limit"):
        v._json('"ああa"')


def test_oversized_text_rejected_before_json_decoder(monkeypatch):
    monkeypatch.setattr(v, "MAX_JSON_BYTES", 8)
    def forbidden(*args, **kwargs):
        raise AssertionError("oversized JSON reached decoder")
    monkeypatch.setattr(v.json, "loads", forbidden)
    with pytest.raises(ValueError, match="byte limit"):
        v._json(' ' * 9)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b"\r"])
def test_original_line_endings_and_unicode_separators_preserved(tmp_path, ending):
    path = tmp_path / "events"
    value = {"text": "literal\u2028and\u2029inside string"}
    line = json.dumps(value, ensure_ascii=False).encode()
    path.write_bytes(ending + line + ending + line)
    assert v.load_events(str(path)) == [value, value]


def test_event_count_limit_never_returns_partial_batch(tmp_path, monkeypatch):
    monkeypatch.setattr(v, "MAX_EVENT_COUNT", 2)
    path = tmp_path / "events"
    path.write_bytes(b'{}\n\n{}\n')
    assert v.load_events(str(path)) == [{}, {}]
    path.write_bytes(b'{}\n{}\n{}\n')
    with pytest.raises(ValueError, match="count"):
        v.load_events(str(path))


def test_event_line_limit_includes_whitespace(tmp_path, monkeypatch):
    monkeypatch.setattr(v, "MAX_JSON_BYTES", 8)
    path = tmp_path / "events"
    path.write_bytes(b'{}     \n')
    assert v.load_events(str(path)) == [{}]
    for data in (b'{}      \n', b' ' * 9, '"ああa"'.encode()):
        path.write_bytes(data)
        with pytest.raises(ValueError, match="byte limit"):
            v.load_events(str(path))


def test_batch_byte_limit_exact_and_plus_one(tmp_path, monkeypatch):
    monkeypatch.setattr(v, "MAX_EVENT_FILE_BYTES", 6)
    path = tmp_path / "events"
    path.write_bytes(b'{}\n{}\n')
    assert v.load_events(str(path)) == [{}, {}]
    path.write_bytes(b'{}\n{}\n\n')
    with pytest.raises(ValueError, match="byte limit"):
        v.load_events(str(path))


@pytest.mark.parametrize("loader,limit_name", [(v.load_security_object, "MAX_JSON_BYTES"),
                                               (v.load_public_key, "MAX_KEY_FILE_BYTES")])
def test_loader_size_check_precedes_decode(tmp_path, monkeypatch, loader, limit_name):
    monkeypatch.setattr(v, limit_name, 8)
    path = tmp_path / "input"
    path.write_bytes(b'\xff' * 9)
    with pytest.raises(ValueError, match="byte limit"):
        loader(str(path))


@pytest.mark.parametrize("encoding", ["raw", "hex", "base64", "json"])
def test_key_encodings_unchanged(tmp_path, encoding):
    key = bytes(range(32))
    formats = {"raw": key, "hex": key.hex().encode(), "base64": base64.b64encode(key),
               "json": json.dumps({"PublicKey": key.hex()}).encode()}
    path = tmp_path / "key"
    path.write_bytes(formats[encoding])
    assert v.load_public_key(str(path)) == key


@pytest.mark.parametrize("loader", LOADERS)
@pytest.mark.parametrize("kind", ["directory", "fifo", "symlink_to_fifo", "device"])
def test_special_file_refused_before_open(tmp_path, monkeypatch, loader, kind):
    path = tmp_path / "input"
    if kind == "directory":
        path.mkdir()
    elif kind == "device":
        path = Path(os.devnull)
    else:
        os.mkfifo(path)
        if kind == "symlink_to_fifo":
            link = tmp_path / "link"
            link.symlink_to(path)
            path = link
    def forbidden(*args, **kwargs):
        raise AssertionError("known special file was opened")
    monkeypatch.setattr(v.os, "open", forbidden)
    with pytest.raises(ValueError, match="regular"):
        loader(str(path))


def test_symlink_to_regular_file_still_supported(tmp_path):
    path = tmp_path / "events"
    path.write_bytes(b'{}\n')
    link = tmp_path / "events-link"
    link.symlink_to(path)
    assert v.load_events(str(link)) == [{}]


def test_open_descriptor_rechecked_and_closed(tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b'{}')
    actual_open = os.open
    opened = []
    def observed(*args, **kwargs):
        fd = actual_open(*args, **kwargs)
        opened.append(fd)
        assert args[1] & os.O_NONBLOCK
        return fd
    monkeypatch.setattr(v.os, "open", observed)
    actual_fstat = os.fstat
    monkeypatch.setattr(v.os, "fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFIFO, st_size=0))
    with pytest.raises(ValueError, match="regular"):
        v._read_regular(str(path), 8)
    with pytest.raises(OSError):
        actual_fstat(opened[0])


def test_actual_read_bound_even_if_stat_size_is_wrong(tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b'123456789')
    real_fstat = os.fstat
    monkeypatch.setattr(v.os, "fstat", lambda fd: SimpleNamespace(
        st_mode=real_fstat(fd).st_mode, st_size=0))
    with pytest.raises(ValueError, match="byte limit"):
        v._read_regular(str(path), 8)


def test_fdopen_failure_closes_descriptor(tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b'{}')
    real_open = os.open
    opened = []
    def observed(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd
    def failed(*args, **kwargs):
        raise OSError("synthetic fdopen failure")
    monkeypatch.setattr(v.os, "open", observed)
    monkeypatch.setattr(v.os, "fdopen", failed)
    with pytest.raises(OSError):
        v._read_regular(str(path), 8)
    with pytest.raises(OSError):
        os.fstat(opened[0])


def run_cli(script, events, extra=()):
    return subprocess.run([sys.executable, str(DIRECTORY / script), str(events), "--json", *extra],
                          capture_output=True, text=True, timeout=5)


def tampered_file(tmp_path):
    event = {"Header": {"EventID": "synthetic", "Sequence": 1}, "Payload": {"n": 1},
             "Security": {"Version": "1.1", "HashAlgo": "SHA256"}}
    event["Security"]["EventHash"] = v.event_content_hash(event)
    event["Payload"]["n"] = 2
    path = tmp_path / "events"
    path.write_text(json.dumps(event) + '\n')
    return path


@pytest.mark.parametrize("script", CLIS)
@pytest.mark.parametrize("kind", ["fifo", "overflow", "depth", "oversized", "invalid_utf8"])
def test_cli_bad_event_input_refused_without_partial_report(tmp_path, script, kind):
    path = tmp_path / "events"
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "overflow":
        path.write_text('{"unused":1e9999}\n')
    elif kind == "depth":
        path.write_text('{"x":' + '[' * 64 + '0' + ']' * 64 + '}')
    elif kind == "oversized":
        with path.open('wb') as f:
            f.truncate(v.MAX_EVENT_FILE_BYTES + 1)
    else:
        path.write_bytes(b'\xff')
    before = path.stat()
    output = tmp_path / "report"
    result = run_cli(script, path, ('--output', str(output)))
    assert result.returncode == 3
    assert "Cannot load events" in result.stderr and "Traceback" not in result.stderr
    assert result.stdout == '' and not output.exists()
    assert path.stat().st_size == before.st_size


@pytest.mark.parametrize("script", CLIS)
@pytest.mark.parametrize("flag", ["--security-object", "--public-key"])
@pytest.mark.parametrize("kind", ["fifo", "oversized", "overflow"])
def test_optional_failure_cannot_hide_loaded_event_mismatch(tmp_path, script, flag, kind):
    events = tampered_file(tmp_path)
    optional = tmp_path / "optional"
    if kind == "fifo":
        os.mkfifo(optional)
    elif kind == "oversized":
        limit = v.MAX_KEY_FILE_BYTES if flag == "--public-key" else v.MAX_JSON_BYTES
        with optional.open('wb') as f:
            f.truncate(limit + 1)
    else:
        optional.write_text('{"unused":1e9999}')
    original = events.read_bytes()
    result = run_cli(script, events, (flag, str(optional)))
    assert result.returncode == 1 and 'Traceback' not in result.stderr
    report = json.loads(result.stdout)
    assert report['status'] == v.INVALID
    assert report['checks']['event_hash']['status'] == v.INVALID
    assert any(c['status'] == v.INDETERMINATE and 'INPUT_UNAVAILABLE' in c['reason']
               for c in report['checks'].values())
    assert events.read_bytes() == original


@pytest.mark.parametrize("kind", ["fifo", "oversized"])
def test_supplemental_attestor_key_uses_bounded_loader(tmp_path, kind):
    events = tampered_file(tmp_path)
    key = tmp_path / "key"
    if kind == "fifo":
        os.mkfifo(key)
    else:
        with key.open('wb') as f:
            f.truncate(v.MAX_KEY_FILE_BYTES + 1)
    result = run_cli('verify_attested_batch.py', events, ('--attestor-key', str(key)))
    assert result.returncode == 1 and 'Traceback' not in result.stderr
    report = json.loads(result.stdout)
    assert report['checks']['attestor_key_input']['status'] == v.INDETERMINATE
    assert report['checks']['event_hash']['status'] == v.INVALID
