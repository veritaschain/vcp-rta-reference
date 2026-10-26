#!/usr/bin/env python3
"""Read-only consistency triage of the fixed RTA recipe's saved reports.

Never executes submitted code, extracts archives, contacts a network or awards
independence/publication permission. A consistent fabricated report can pass.
Use a reviewed checkout and a stationary, unpacked Linux report directory.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = 'docs/REPRODUCTION_CHECKPOINT_2026-10-26.json'
REFERENCE_SHA256 = '296d6f468cf0a4b67d297e2208bdb820a1fbd7cba46fae0164c9cb30b1e5ca24'
REPLAY_SHA256 = '077a9ab39911bbec06cb122e73e6ba67104f3c8a1d93bfa37aba762ca5fc12bf'
FILES = (
    'guide-commit.txt', 'checkpoint.json', 'reviewer-report-template.md', 'pip-freeze.txt',
    'openssl-version.txt', 'input-check.json', 'historical.xml', 'historical.log',
    'historical.exit', 'historical-pack.json', 'replay.exit', 'review-assessment.json',
    'review-files.sha256.json', 'regression/run.json', 'regression/pytest.log',
    'regression/junit.xml', 'regression/artifacts.sha256.json',
)
MAX_FILE = 16 * 1024 * 1024
MAX_JSON = 2 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(root: Path, name: str, limit: int) -> bytes:
    """Only fixed caller-code paths are passed here; manifest paths are not opened."""
    path = root / name
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink():
            raise ValueError('SYMLINK_DIRECTORY')
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('NOT_REGULAR_OR_OVERSIZED')
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('OVERSIZED')
    return data


def load_json(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('NONFINITE_JSON_NUMBER')
    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError('NONFINITE_JSON_NUMBER')
        return result
    result = json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                        parse_constant=constant, parse_float=number)
    if not isinstance(result, dict):
        raise ValueError('JSON_OBJECT_REQUIRED')
    return result


def encoded(value) -> bytes:
    # Local report comparison only, NOT JCS or VCP signing/canonicalization.
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def trusted_context():
    data = read_regular(ROOT, REFERENCE, MAX_JSON)
    if sha(data) != REFERENCE_SHA256:
        raise ValueError('LOCAL_REFERENCE_DIFFERS')
    reference = load_json(data)
    name = 'tools/verifier/run_regression.py'
    source = read_regular(ROOT, name, MAX_FILE)
    if sha(source) != reference['input_sha256'][name]:
        raise ValueError('LOCAL_JUNIT_ASSESSOR_DIFFERS')
    # This is checked LOCAL repository code, never a submitted Python module.
    spec = importlib.util.spec_from_file_location('intake_local_assessor', ROOT / name)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, str(ROOT / name), 'exec'), module.__dict__)
    return reference, module


class SnapshotXML:
    """Feed already bounded report bytes to the unchanged local JUnit reader."""
    def __init__(self, data):
        self.data = data

    def open(self, mode):
        if mode != 'rb':
            raise ValueError('READ_ONLY')
        return io.BytesIO(self.data)


def inspect(directory: Path) -> dict:
    reference, reader = trusted_context()
    directory = Path(os.path.abspath(directory))
    problems, data, parsed, checks, warnings = [], {}, {}, {}, []
    total = 0
    for name in FILES:
        try:
            raw = read_regular(directory, name, MAX_JSON if name.endswith('.json') else MAX_FILE)
            total += len(raw)
            if total > MAX_TOTAL:
                raise ValueError('TOTAL_LIMIT')
            data[name] = raw
            if name.endswith('.json'):
                parsed[name] = load_json(raw)
        except FileNotFoundError:
            problems.append('MISSING:' + name)
        except (OSError, ValueError, RecursionError):
            problems.append('UNUSABLE:' + name)
        if total > MAX_TOTAL:
            problems.append('REPORT_TOTAL_LIMIT')
            break

    def equal(name, actual, expected):
        matched = encoded(actual) == encoded(expected)
        checks[name] = matched
        if not matched:
            problems.append('DIFFERS:' + name)

    def manifest(name, expected):
        supplied = parsed.get(name, {})
        # Compare only a fixed key set. Never read a submitted filename or URL.
        equal(name + ':members', sorted(supplied), sorted(expected))
        for key in sorted(expected):
            equal(name + ':' + key, supplied.get(key), sha(data[key]) if key in data else None)
            if key not in data:
                checks[name + ':' + key] = False

    manifest('review-files.sha256.json', set(FILES) - {'review-files.sha256.json'})
    short = parsed.get('regression/artifacts.sha256.json', {})
    equal('regression_manifest', short, {
        name: sha(data['regression/' + name]) if 'regression/' + name in data else None
        for name in ('run.json', 'pytest.log', 'junit.xml')})
    equal('checkpoint_bytes', sha(data.get('checkpoint.json', b'')), REFERENCE_SHA256)
    equal('guide_commit_record', bool(re.fullmatch(rb'[0-9a-f]{40}\n?', data.get('guide-commit.txt', b''))), True)
    target = reference['checkout_commit']
    run = parsed.get('regression/run.json', {})
    assessment = parsed.get('review-assessment.json', {})
    replay = parsed.get('historical-pack.json', {})
    initial = parsed.get('input-check.json', {})
    for label, obj, key in (('run', run, 'git_head'), ('assessment', assessment, 'executed_commit'),
                            ('replay', replay, 'executed_commit'), ('input', initial, 'commit')):
        equal(label + ':target', obj.get(key), target)
    for key in ('inputs_before_sha256', 'inputs_after_sha256'):
        equal(key, run.get(key), reference['input_sha256'])
    equal('input_check', initial.get('input_sha256'), reference['input_sha256'])
    equal('input_reference', initial.get('checkpoint_json_sha256'), REFERENCE_SHA256)
    equal('run_status', run.get('run_status'), 'passed')
    equal('run_problems', run.get('problems'), [])
    equal('pytest_exit', run.get('pytest_exit'), 0)
    equal('historical_exit', data.get('historical.exit', b'').strip().decode('ascii', 'replace'), '0')
    equal('replay_exit', data.get('replay.exit', b'').strip().decode('ascii', 'replace'), '2')
    suites = reference['test_expectations']['regression_by_suite']
    main = reader.assess_junit(SnapshotXML(data.get('regression/junit.xml', b'')), 0, suites)
    historical = reader.assess_junit(SnapshotXML(data.get('historical.xml', b'')), 0,
                                     {'test_historical_evidence': 15})
    for label, result, counts in (('main', main, suites),
                                   ('historical', historical, {'test_historical_evidence': 15})):
        equal(label + ':xml', result,
              {'passed': True, 'cases': sum(counts.values()), 'by_suite': counts, 'problems': []})
        equal(label + ':summary', assessment.get(label), result)
    equal('run_junit', run.get('junit'), main)
    for key, expected in (('checkpoint', reference['checkpoint_id']),
                          ('reproduction_matches_reference', True), ('problems', []),
                          ('evidence_verdict', 'INDETERMINATE'), ('conformance_claim', False),
                          ('independence_assessment', 'not assessed by this script')):
        equal('assessment:' + key, assessment.get(key), expected)
    stable = {key: value for key, value in replay.items() if key not in ('environment', 'executed_commit')}
    equal('complete_replay_projection', sha(encoded(stable)), REPLAY_SHA256)
    inventory = {'passed': True, 'regression_files': sorted(name + '.py' for name in suites),
                 'separate_files': ['test_historical_evidence.py'],
                 'discovered_files': sorted([name + '.py' for name in suites] + ['test_historical_evidence.py']),
                 'problems': []}
    equal('test_inventory', run.get('test_inventory'), inventory)
    environment = run.get('environment')
    environment = environment if isinstance(environment, dict) else {}
    equal('environment_present', all(isinstance(environment.get(key), str) and environment[key]
          for key in ('python', 'platform', 'openssl', 'openssl_executable')), True)
    equal('direct_dependencies', environment.get('dependencies'), reference['reference_environment']['direct_dependencies'])
    replay_environment = replay.get('environment')
    replay_environment = replay_environment if isinstance(replay_environment, dict) else {}
    equal('replay_python', replay_environment.get('python'), environment.get('python'))
    equal('replay_cryptography', replay_environment.get('cryptography'),
          reference['reference_environment']['direct_dependencies']['cryptography'])
    command = run.get('command')
    equal('command_record', isinstance(command, list) and bool(command)
          and all(isinstance(item, str) for item in command)
          and sorted(item for item in command if item.startswith('tests/'))
              == sorted('tests/' + name + '.py' for name in suites), True)
    if environment.get('python') not in reference['reference_environment']['python']:
        warnings.append('PYTHON_DIFFERS_FROM_RECORDED_ENVIRONMENTS')
    if not str(environment.get('openssl', '')).startswith('OpenSSL ' + reference['reference_environment']['openssl'] + ' '):
        warnings.append('OPENSSL_DIFFERS_FROM_RECORDED_ENVIRONMENTS')
    problems = sorted(set(problems))
    return {'format': 'vcp-rta-report-intake-v1',
            'status': 'REVIEW_REQUIRED' if problems else 'REPORTS_MATCH_REFERENCE',
            'checkpoint': reference['checkpoint_id'], 'problems': problems, 'warnings': warnings, 'checks': checks,
            'read_file_sha256': {name: sha(raw) for name, raw in sorted(data.items())},
            'reference_sha256': REFERENCE_SHA256, 'tests_rerun': False,
            'independence': 'NOT_ASSESSED', 'publication_permission': 'NOT_ASSESSED',
            'conformance_claim': False,
            'scope': 'Saved-report consistency only; not execution authenticity, identity or cryptographic reverification.'}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report_directory', type=Path, help='Unpacked recipe output, not a ZIP or code checkout')
    args = parser.parse_args(argv)
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
        parser.error('This reader requires POSIX O_NOFOLLOW; use the documented Linux setup')
    try:
        result = inspect(args.report_directory)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print(json.dumps({'status': 'CHECKER_ERROR', 'error_type': type(exc).__name__,
                          'tests_rerun': False, 'conformance_claim': False}))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'REPORTS_MATCH_REFERENCE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
