"""Offline only: synthetic cookies/codes; never contact real accounts."""
import contextlib
import io
import json
import threading
import unittest
import urllib.request
from types import SimpleNamespace
from unittest.mock import Mock, patch

import garena_api_test_chrome1 as api
import kientuong_auth as auth


def response(body, status=200):
    return status, 'https://auth.garena.com/', 'application/json', body


class KientuongGrantTests(unittest.TestCase):
    def session(self, responses):
        session = api.WebSession(1)
        session.request = Mock(side_effect=responses)
        return session

    def params(self):
        return dict(client_id='100054', redirect_uri=auth.CALLBACK, response_type='code')

    def test_code_flow_and_explicit_consent(self):
        callback = auth.CALLBACK + '?code=SYNTHETIC-CODE'
        session = self.session([response({'sso_session': {'login': True}, 'error': 'error_require_grant'}),
                                response({'redirect_uri': callback}), response({})])
        result, logged = session.oauth_callback('synthetic', 'unused', self.params(), ensure_login=False)
        self.assertTrue(result['ok'])
        self.assertTrue(logged)
        form = session.request.call_args_list[1].kwargs['form_body']
        self.assertEqual(form['create_grant'], 'true')
        self.assertEqual(form['response_type'], 'code')
        self.assertEqual(form['client_id'], '100054')
        public = {k: v for k, v in result.items() if not k.startswith('_')}
        self.assertNotIn('SYNTHETIC-CODE', json.dumps(public))

    def test_grant_cached_on_success_denial_and_timeout(self):
        for item in (response({'redirect_uri': auth.CALLBACK + '?code=x'}),
                     response({'error': 'error_require_grant'}),
                     response({'error': 'secret-token-echo'}, 403), TimeoutError('secret-password')):
            session = self.session([item])
            first = auth.code_grant(session, self.params())
            self.assertEqual(auth.code_grant(session, self.params()), first)
            self.assertEqual(session.request.call_count, 1)
            self.assertNotIn('secret-', json.dumps(first))

    def test_account_sessions_and_cookies_are_isolated(self):
        first, second = self.session([response({})]), self.session([response({})])
        auth.code_grant(first, self.params())
        auth.code_grant(second, self.params())
        self.assertIsNot(first.cookies, second.cookies)
        self.assertIsNot(first._code_grants, second._code_grants)
        self.assertEqual(second.request.call_count, 1)

    def test_no_grant_after_init_denial(self):
        for status, body in ((403, {}), (429, {}), (200, {'error': 'error_captcha'}),
                             (200, {'error': 'error_access_denied'})):
            session = self.session([response(body, status)])
            result, _ = session.oauth_callback('synthetic', 'unused', self.params(), ensure_login=False)
            self.assertFalse(result['ok'])
            self.assertTrue(auth.terminal_authorization(result))
            self.assertEqual(session.request.call_count, 1)

    def test_callback_validation(self):
        for url in ('https://evil.example/?code=x', auth.CALLBACK,
                    auth.CALLBACK + '?code=x&code=y', auth.CALLBACK + '?code=x&error=denied',
                    auth.CALLBACK + '?code=x#fragment', auth.CALLBACK.replace('https:', 'http:') + '?code=x'):
            session = self.session([response({'sso_session': {'login': True}}), response({'redirect_uri': url})])
            result, _ = session.oauth_callback('synthetic', 'unused', self.params(), ensure_login=False)
            self.assertFalse(result['ok'])
            self.assertEqual(session.request.call_count, 2)

    def test_redirect_guard_does_not_replay_post_or_send_code_elsewhere(self):
        guard = auth.OAuthRedirectGuard()
        for status in (301, 302, 303, 307, 308):
            self.assertIsNone(guard.redirect_request(urllib.request.Request(auth.GRANT, data=b'x'),
                None, status, '', {}, auth.CALLBACK + '?code=x'))
        self.assertIsNone(guard.redirect_request(urllib.request.Request(auth.CALLBACK + '?code=x'),
            None, 302, '', {}, 'https://evil.example/'))

    def test_game_client_target_rejected_without_http(self):
        session = self.session([])
        params = self.params()
        params['client_id'] = '100055'
        self.assertEqual(auth.code_grant(session, params)[0], 0)
        session.request.assert_not_called()

    def bridge(self, oauth, grant=None, callback_status=200, player=None):
        replies = [response({'sso_session': {'login': True}}), response(oauth)]
        if grant is not None:
            replies.append(response(grant))
        callback = (grant or oauth).get('redirect_uri')
        if callback and auth.valid_code_callback(callback):
            replies.append(response({}, callback_status))
        session = self.session(replies)
        session.api_result = Mock(return_value=player or {'ok': True, 'body': {'player': {'level': 5}}})
        with patch.object(api, 'WebSession', return_value=session), \
                patch.object(api, 'fetch_latest_lien_quan_login', return_value={}), patch.object(api.time, 'sleep'):
            result = api.legacy_account_sso_probe('SYNTHETIC-SSO', 9999999999, 1)
        return result, session

    def test_bridge_grants_and_reads_in_same_session(self):
        result, session = self.bridge({'sso_session': {'login': True}, 'error': 'error_require_grant'},
                                     {'redirect_uri': auth.CALLBACK + '?code=x'})
        chain = result['account_to_kientuong_oauth']
        self.assertTrue(chain['ok'])
        self.assertIsNone(chain['error'])
        self.assertFalse(api.kientuong_requires_grant(result))
        self.assertEqual(chain['player_attempts'], 1)
        self.assertEqual(session.request.call_count, 4)

    def test_bridge_failed_callback_never_reads_player(self):
        result, session = self.bridge({'sso_session': {'login': True}},
                                     {'redirect_uri': auth.CALLBACK + '?code=x'}, callback_status=403)
        self.assertTrue(auth.terminal_authorization(result['account_to_kientuong_oauth']))
        self.assertEqual(session.api_result.call_count, 1)  # account/init only

    def test_bridge_player_denial_stops_and_422_is_not_missing_role(self):
        for status in (403, 429, 422):
            result, session = self.bridge({'sso_session': {'login': True}},
                {'redirect_uri': auth.CALLBACK + '?code=x'},
                player={'ok': False, 'status': status, 'body': {}})
            chain = result['account_to_kientuong_oauth']
            self.assertEqual(chain['player_attempts'], api.KIENTUONG_MAX_ATTEMPTS if status == 422 else 1)
            self.assertEqual(chain['no_character_responses'], 0)
            self.assertTrue(auth.terminal_authorization(chain))

    def test_blocked_or_unconfirmed_results_keep_requested_export_tag(self):
        for player in ({'ok': False, 'status': 403}, {'ok': False, 'status': 429},
                       {'ok': False, 'status': 422, 'body': {}},
                       {'ok': True, 'status': 200, 'body': {}},
                       {'ok': True, 'body': {'player': {'level': 0}}}):
            stop, gate = Mock(), Mock()
            stop.wait.return_value = False
            gate.wait.return_value = True
            with patch.object(api, 'run_api_tests', return_value={'tcp': {'ok': True},
                         'apis': {'kientuong_player': player}}), contextlib.redirect_stdout(io.StringIO()):
                row = api.batch_check_one(api.BatchAccount(1, 'synthetic', 'unused'), None, 1, gate, stop)
            self.assertEqual((row['status'], row['result_type'], row['level']), ('OK', 'Lỗi CTNV', ''))

    def test_valid_level_stays_numeric(self):
        self.assertTrue(api.kientuong_player_has_level({'ok': True, 'body': {'player': {'level': 5}}}))
        for level in (0, -1, 31, '', None, True, 'unknown'):
            self.assertFalse(api.kientuong_player_has_level({'ok': True, 'body': {'player': {'level': level}}}))

    def test_run_api_does_not_open_second_session_after_grant_or_player_failure(self):
        for chain in ({'grant_status': 403, 'terminal_authorization': True},
                      {'grant_status': 200, 'terminal_authorization': True,
                       'player_api': {'ok': False, 'status': 422, 'body': {}}},
                      {'grant_error': 'error_require_grant'}):
            client = Mock()
            client.login.return_value = 123
            client.session_key = b'x'
            client.ignored_server_commands = []
            client.get_sso_key.return_value = SimpleNamespace(sso_key='synthetic-sso', expiry_time=9999999999)
            manager = contextlib.nullcontext((client, 123))
            with patch.object(api, 'login_with_proxy_fallback', return_value=manager), \
                    patch.object(api, 'resilient_tcp_client_type'), \
                    patch.object(api, 'legacy_account_sso_probe', return_value={
                        'accepted': True, 'account_to_kientuong_oauth': chain}), \
                    patch.object(api, 'WebSession', side_effect=AssertionError('No second web session')):
                result = api.run_api_tests(SimpleNamespace(), 'synthetic', 'unused', 1)
            self.assertTrue(result['tcp']['ok'])

    def test_prelogin_denial_is_not_retried(self):
        session = self.session([response({'error': 'error_captcha'}, 403)])
        result = session._credential_login('auth.garena.com', '100054', 'synthetic', 'unused', auth.CALLBACK)
        self.assertFalse(result['ok'])
        self.assertEqual(session.request.call_count, 1)

    def test_formatted_output_does_not_expose_sso(self):
        result = api.format_user_output({'tcp': {'account': 'synthetic', 'web_sso_key': 'SYNTHETIC-SSO'}})
        self.assertNotIn('SYNTHETIC-SSO', result)
        self.assertNotIn('Chưa tạo nhân vật', result)


if __name__ == '__main__':
    unittest.main()
