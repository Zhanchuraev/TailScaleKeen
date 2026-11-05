"""Regression tests for request isolation, storage failures and private reports."""
import contextlib, json, pathlib, tempfile, time, unittest
from unittest.mock import patch
import test_panel as base
from panel.core import Error, Jobs, read_json, write_json
from panel.health import inspect
from panel.service import Service


class AuditHTTPTests(unittest.TestCase):
    setUp = base.AuthHTTPTests.setUp
    tearDown = base.AuthHTTPTests.tearDown
    req = base.AuthHTTPTests.req
    login = base.AuthHTTPTests.login
    anonymous = base.AuthHTTPTests.anonymous

    def test_public_session_flood_cannot_logout_owner(self):
        self.login()
        cookie = self.cookie
        for _ in range(350):
            self.app.create_session()
        self.assertEqual(self.req('/api/dashboard', headers={'Cookie': cookie})[0], 200)
        self.assertLessEqual(sum(not s['user'] for s in self.app.sessions.values()), 64)

    def test_authenticated_and_anonymous_budgets_are_bounded_separately(self):
        for _ in range(150): self.app.create_session('admin')
        for _ in range(100): self.app.create_session()
        self.assertEqual(sum(bool(s['user']) for s in self.app.sessions.values()), 128)
        self.assertEqual(sum(not s['user'] for s in self.app.sessions.values()), 64)

    def test_expired_failure_addresses_are_pruned(self):
        self.app.failures.update({str(i): [time.time()-301] for i in range(800)})
        self.assertTrue(self.app.throttled('test', lambda: True))
        self.assertLessEqual(len(self.app.failures), 1)

    def test_health_and_support_report_require_login(self):
        for path in ['/api/health', '/api/support-report']:
            self.assertEqual(self.req(path)[0], 401)
        self.login()
        status, data, headers = self.req('/api/support-report')
        self.assertEqual(status, 200)
        self.assertIn('attachment;', headers['Content-Disposition'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(data['schema'], 1)

    def test_report_never_copies_private_values_even_from_errors(self):
        self.login()
        marker = 'private-sensitive-marker'
        runner = self.app.service.runner
        runner.prefs['ControlURL'] = 'https://' + marker + '.example.test'
        runner.prefs['Persist'] = {'PrivateNodeKey': marker}
        runner.status['Self']['HostName'] = marker
        runner.status['Self']['TailscaleIPs'] = ['100.64.250.123']
        runner.status['Health'] = [marker]
        runner.status['BackendState'] = marker
        write_json(self.state/'devices.json', {'notes': marker})
        self.app.service.ts.invalidate()
        status, result, _ = self.req('/api/support-report')
        text = json.dumps(result)
        for secret in [marker, '100.64.250.123', self.state.as_posix(), self.app.auth_record()['password_hash']]:
            self.assertNotIn(secret, text)
        self.assertEqual(result['backend_state'], 'Unknown')
        self.assertEqual(result['network']['health_warning_count'], 1)

    def test_static_cache_revalidates_and_changes_with_content(self):
        status, content, headers = self.req('/static/app.js')
        self.assertEqual(status, 200)
        self.assertIn('must-revalidate', headers['Cache-Control'])
        status, body, response = self.req('/static/app.js', headers={'If-None-Match': headers['ETag']})
        self.assertEqual(status, 304)
        self.assertEqual(body, b'')
        self.assertEqual(response['ETag'], headers['ETag'])
        self.assertNotIn('Content-Type', response)
        self.assertNotIn('Content-Length', response)
        self.assertEqual(self.req('/static/app.js', headers={'If-None-Match': '"stale"'})[0], 200)
        self.assertEqual(self.req('/api/session')[2]['Cache-Control'], 'no-store')

    def test_cancel_preview_requires_auth_csrf_and_removes_secret(self):
        self.login()
        status, plan, _ = self.req('/api/actions/plan', {'action': 'connect', 'params': {'auth_key': 'temporary-fixture-key'}})
        self.assertEqual(status, 200)
        params = self.app.service.plans[plan['id']]['params']
        self.assertEqual(self.req('/api/actions/cancel', {'plan_id': plan['id']}, {'X-CSRF-Token': 'wrong'})[0], 403)
        self.assertEqual(self.req('/api/actions/cancel', {'plan_id': plan['id']})[0], 200)
        self.assertNotIn('auth_key', params)
        self.assertNotIn(plan['id'], self.app.service.plans)


class AuditServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.service = Service(self.tmp.name, base.FakeRunner())

    def test_expired_previews_remove_registration_key(self):
        plan = self.service.plan('connect', {'auth_key': 'temporary-fixture-key'})
        record = self.service.plans[plan['id']]
        record['expires'] = time.time()-1
        self.service.prune_plans()
        self.assertFalse(self.service.plans)
        self.assertNotIn('auth_key', record['params'])

    def test_pending_previews_have_a_memory_limit(self):
        self.service.panel_updater.check = lambda *_: {'latest': '9.0.0', 'available': True}
        for _ in range(32): self.service.plan('update_panel', {})
        with self.assertRaises(Error): self.service.plan('update_panel', {})
        self.assertEqual(len(self.service.plans), 32)

    def test_preference_change_while_worker_waits_prevents_write(self):
        plan = self.service.plan('settings', {'accept_dns': True})
        def delayed_worker(label, work):
            self.service.runner.prefs['Hostname'] = 'changed-after-request'
            return work(lambda _: None)
        with patch.object(self.service.jobs, 'start', delayed_worker), self.assertRaises(Error):
            self.service.apply(plan['id'])
        self.assertFalse(any('set' in call for call in self.service.runner.calls))

    def test_tsmp_uses_only_known_peer_and_does_not_change_preferences(self):
        def immediate(label, work): return work(lambda _: None)
        with patch.object(self.service.jobs, 'start', immediate):
            self.service.diagnostics('tsmp', '100.64.250.7')
            for target in ['8.8.8.8', '--evil', {}]:
                with self.assertRaises(Error): self.service.diagnostics('tsmp', target)
        command = next(c for c in self.service.runner.calls if '--tsmp' in c)
        self.assertIn('--until-direct=false', command)
        self.assertEqual(command[-1], '100.64.250.7')

    def test_health_warning_for_unreadable_client_does_not_leak_exception(self):
        with patch.object(self.service.ts, 'snapshot', side_effect=Error('private-sensitive-marker')):
            result = inspect(self.service, root=self.tmp.name)
        self.assertNotIn('private-sensitive-marker', json.dumps(result))
        self.assertEqual(result['backend_state'], 'Unavailable')
        self.assertEqual(result['checks'][0]['state'], 'warn')

    def test_report_warns_on_permissive_auth_file(self):
        path = self.service.state / 'auth.json'
        write_json(path, {'password_hash': 'synthetic'})
        path.chmod(0o644)
        result = inspect(self.service, root=self.tmp.name)
        check = next(x for x in result['checks'] if x['id']=='permissions')
        self.assertEqual(check['state'], 'warn')

    def test_health_coalesces_repeated_reads(self):
        with patch('panel.health.inspect', return_value={'schema': 1}) as inspect_:
            self.service.health(); self.service.health()
        self.assertEqual(inspect_.call_count, 1)


class JobStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.jobs = Jobs(self.tmp.name)
        self.patch = patch('panel.core.operation_lock', lambda _: contextlib.nullcontext())
        self.patch.start(); self.addCleanup(self.patch.stop)

    def assert_next_job_works(self):
        job = self.jobs.start('after storage failure', lambda _: {'ok': True})
        until = time.monotonic()+3
        while time.monotonic()<until and self.jobs.lock.locked(): time.sleep(0.01)
        self.assertFalse(self.jobs.lock.locked())
        self.assertEqual(self.jobs.get(job['id'])['state'], 'done')

    def test_failure_while_scheduling_does_not_lock_future_jobs(self):
        with patch('panel.core.write_json', side_effect=OSError('test volume unavailable')):
            with self.assertRaises(OSError): self.jobs.start('fails', lambda _: {})
        self.assert_next_job_works()

    def test_failure_during_pruning_does_not_lock_future_jobs(self):
        with patch.object(self.jobs, 'prune', side_effect=OSError('test volume unavailable')):
            with self.assertRaises(OSError): self.jobs.start('fails', lambda _: {})
        self.assert_next_job_works()

    def test_failure_persisting_finished_job_releases_lock(self):
        with patch('panel.core.threading.Thread') as thread:
            self.jobs.start('fails writing final result', lambda _: {'ok': True})
            target = thread.call_args.kwargs['target']
        with patch('panel.core.write_json', side_effect=OSError('test volume unavailable')):
            with self.assertRaises(OSError): target()
        self.assert_next_job_works()

    def test_thread_start_failure_releases_lock(self):
        with patch('panel.core.threading.Thread.start', side_effect=RuntimeError('test thread limit')):
            with self.assertRaises(RuntimeError): self.jobs.start('fails', lambda _: {})
        self.assert_next_job_works()
