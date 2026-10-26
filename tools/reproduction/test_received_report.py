"""Synthetic saved-report fixtures, not proof of execution or cryptography.

Only the replay projection fingerprint is substituted for fixture construction.
CI separately checks the unmodified reader against a real fresh recipe output.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('received_reader', Path(__file__).with_name('check_received_report.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def xml(counts):
    root = ET.Element('testsuites')
    for name, count in counts.items():
        suite = ET.SubElement(root, 'testsuite', tests=str(count), failures='0', errors='0', skipped='0')
        for index in range(count):
            case = ('test_real_rfc3161_response_signature_chain_and_imprint'
                    if name == 'test_attested_batch' and index == 0 else 'test_%d' % index)
            ET.SubElement(suite, 'testcase', classname='tests.' + name, name=case)
    return ET.tostring(root, encoding='utf-8')


class ReceivedReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / 'received'
        self.directory.mkdir()
        self.reference, reader = c.trusted_context()
        ref = self.reference
        suites = ref['test_expectations']['regression_by_suite']
        self.write('regression/junit.xml', xml(suites))
        self.write('historical.xml', xml({'test_historical_evidence': 15}))
        main = reader.assess_junit(self.directory / 'regression/junit.xml', 0, suites)
        history = reader.assess_junit(self.directory / 'historical.xml', 0, {'test_historical_evidence': 15})
        self.put('checkpoint.json', ref)
        self.write('checkpoint.json', (c.ROOT / c.REFERENCE).read_bytes())
        self.write('guide-commit.txt', b'a' * 40 + b'\n')
        self.write('historical.exit', b'0\n')
        self.write('replay.exit', b'2\n')
        self.put('input-check.json', {'commit': ref['checkout_commit'], 'input_sha256': ref['input_sha256'],
                                    'checkpoint_json_sha256': c.REFERENCE_SHA256})
        environment = {'python': '3.11.17', 'platform': 'synthetic Linux', 'openssl_executable': '/usr/bin/openssl',
                       'openssl': 'OpenSSL 3.0.13 synthetic', 'dependencies': ref['reference_environment']['direct_dependencies']}
        self.put('regression/run.json', {'git_head': ref['checkout_commit'], 'run_status': 'passed',
            'pytest_exit': 0, 'problems': [], 'environment': environment,
            'inputs_before_sha256': ref['input_sha256'], 'inputs_after_sha256': ref['input_sha256'],
            'command': ['python', '-m', 'pytest'] + ['tests/' + name + '.py' for name in suites],
            'junit': main, 'test_inventory': {'passed': True,
              'regression_files': sorted(name + '.py' for name in suites),
              'separate_files': ['test_historical_evidence.py'],
              'discovered_files': sorted([name + '.py' for name in suites] + ['test_historical_evidence.py']), 'problems': []}})
        self.put('review-assessment.json', {'checkpoint': ref['checkpoint_id'], 'executed_commit': ref['checkout_commit'],
            'reproduction_matches_reference': True, 'problems': [], 'main': main, 'historical': history,
            'evidence_verdict': 'INDETERMINATE', 'conformance_claim': False,
            'independence_assessment': 'not assessed by this script'})
        replay = dict(ref['replay_expectations'], executed_commit=ref['checkout_commit'],
                      environment={'python': '3.11.17', 'cryptography': '46.0.4'}, synthetic_fixture=True)
        self.put('historical-pack.json', replay)
        stable = {k: v for k, v in replay.items() if k not in ('executed_commit', 'environment')}
        patched = patch.object(c, 'REPLAY_SHA256', c.sha(c.encoded(stable)))
        patched.start()
        self.addCleanup(patched.stop)
        for name in c.FILES:
            if not (self.directory / name).exists():
                self.write(name, b'synthetic log or blank template\n')
        self.rehash()

    def write(self, name, data):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def put(self, name, obj):
        self.write(name, json.dumps(obj).encode())

    def read(self, name):
        return json.loads((self.directory / name).read_bytes())

    def rehash(self):
        self.put('regression/artifacts.sha256.json', {name: c.sha((self.directory / 'regression' / name).read_bytes())
                 for name in ('run.json', 'junit.xml', 'pytest.log')})
        self.put('review-files.sha256.json', {name: c.sha((self.directory / name).read_bytes())
                 for name in c.FILES if name != 'review-files.sha256.json'})

    def rejected(self):
        result = c.inspect(self.directory)
        self.assertEqual(result['status'], 'REVIEW_REQUIRED')
        self.assertTrue(result['problems'])
        self.assertFalse(result['conformance_claim'])
        self.assertEqual(result['independence'], 'NOT_ASSESSED')
        return result

    def test_consistent_reports_are_read_only_not_independence(self):
        before = {n: (self.directory / n).read_bytes() for n in c.FILES}
        result = c.inspect(self.directory)
        self.assertEqual(result['status'], 'REPORTS_MATCH_REFERENCE', result['problems'])
        self.assertFalse(result['tests_rerun'])
        self.assertEqual(result['publication_permission'], 'NOT_ASSESSED')
        self.assertEqual(before, {n: (self.directory / n).read_bytes() for n in c.FILES})

    def test_manifest_path_is_never_followed(self):
        obj = self.read('review-files.sha256.json')
        obj['../../outside-secret'] = '0' * 64
        self.put('review-files.sha256.json', obj)
        self.rejected()

    def test_submitted_python_is_not_imported_or_executed(self):
        self.write('run_regression.py', b'raise RuntimeError("NEVER EXECUTE")')
        self.assertEqual(c.inspect(self.directory)['status'], 'REPORTS_MATCH_REFERENCE')

    def test_report_directory_symlink_is_refused(self):
        other = self.directory.parent / 'link'
        other.symlink_to(self.directory, target_is_directory=True)
        self.assertEqual(c.inspect(other)['status'], 'REVIEW_REQUIRED')

    def test_report_file_symlink_is_refused(self):
        path = self.directory / 'historical.log'
        path.unlink()
        path.symlink_to(self.directory / 'pip-freeze.txt')
        self.rejected()

    def test_fifo_is_refused_without_waiting(self):
        path = self.directory / 'historical.log'
        path.unlink()
        os.mkfifo(path)
        self.rejected()

    def test_oversized_file_is_refused(self):
        with (self.directory / 'historical.log').open('wb') as handle:
            handle.truncate(c.MAX_FILE + 1)
        self.rejected()

    def test_total_limit_is_refused(self):
        with patch.object(c, 'MAX_TOTAL', 64):
            self.rejected()

    def test_local_reference_changed_is_checker_error(self):
        with patch.object(c, 'REFERENCE_SHA256', '0' * 64):
            with self.assertRaises(ValueError):
                c.inspect(self.directory)

    def test_nonfinite_and_duplicate_json_are_refused(self):
        for data in (b'{"x":NaN}', b'{"x":1e9999}', b'{"x":1,"x":2}', b'[]'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                c.load_json(data)

    def test_junit_failure_remains_failure_after_rehash(self):
        path = self.directory / 'regression/junit.xml'
        tree = ET.parse(path)
        suite = tree.getroot()[0]
        suite.set('failures', '1')
        ET.SubElement(suite[0], 'failure')
        tree.write(path, encoding='utf-8')
        self.rehash()
        self.rejected()

    def test_missing_file_does_not_hide_different_target(self):
        (self.directory / 'historical.xml').unlink()
        obj = self.read('regression/run.json'); obj['git_head'] = '0' * 40
        self.put('regression/run.json', obj)
        result = self.rejected()
        self.assertIn('MISSING:historical.xml', result['problems'])
        self.assertIn('DIFFERS:run:target', result['problems'])

    def test_cli_missing_directory_returns_nonzero_json(self):
        process = subprocess.run([sys.executable, str(Path(c.__file__)), str(self.directory / 'absent')],
                                 capture_output=True, timeout=10, check=False)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(json.loads(process.stdout)['status'], 'REVIEW_REQUIRED')


# Each mutation has its own unittest ID; subtests above are not inflated counts.
MUTATIONS = {
    'wrong_run_commit': ('regression/run.json', 'git_head', '0' * 40),
    'wrong_assessment_commit': ('review-assessment.json', 'executed_commit', '0' * 40),
    'wrong_replay_commit': ('historical-pack.json', 'executed_commit', '0' * 40),
    'wrong_initial_commit': ('input-check.json', 'commit', '0' * 40),
    'wrong_inputs_before': ('regression/run.json', 'inputs_before_sha256', {}),
    'wrong_inputs_after': ('regression/run.json', 'inputs_after_sha256', {}),
    'wrong_initial_inputs': ('input-check.json', 'input_sha256', {}),
    'failed_run': ('regression/run.json', 'run_status', 'failed'),
    'false_exit': ('regression/run.json', 'pytest_exit', False),
    'wrong_main_exit': ('regression/run.json', 'pytest_exit', 1),
    'false_success': ('review-assessment.json', 'reproduction_matches_reference', 1),
    'false_scope': ('review-assessment.json', 'conformance_claim', 0),
    'wrong_total': ('review-assessment.json', 'main', {'passed': True, 'cases': 809, 'by_suite': {}, 'problems': []}),
    'wrong_replay_verdict': ('historical-pack.json', 'evidence_verdict', 'VALID'),
    'wrong_replay_count': ('historical-pack.json', 'event_count', 39),
    'wrong_replay_root': ('historical-pack.json', 'legacy_merkle_root', '0' * 64),
    'missing_environment': ('regression/run.json', 'environment', {}),
    'missing_command': ('regression/run.json', 'command', []),
    'missing_inventory': ('regression/run.json', 'test_inventory', {}),
    'invented_independence': ('review-assessment.json', 'independence_assessment', 'independent'),
}
for name, (filename, key, value) in MUTATIONS.items():
    def test(self, filename=filename, key=key, value=value):
        obj = self.read(filename); obj[key] = copy.deepcopy(value)
        self.put(filename, obj)
        self.rehash()  # Consistent manifests must not conceal semantic changes.
        self.rejected()
    setattr(ReceivedReportTests, 'test_' + name, test)
for index, name in enumerate(c.FILES):
    def test(self, name=name):
        (self.directory / name).unlink()
        result = self.rejected()
        self.assertIn('MISSING:' + name, result['problems'])
    setattr(ReceivedReportTests, 'test_missing_file_%02d' % index, test)


if __name__ == '__main__':
    unittest.main()
