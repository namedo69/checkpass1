"""Synthetic tests: no target execution, real sockets, or HTTP requests."""
import gzip
import io
import json
import socket
import struct
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent / 'uplv_runtime/pve_backend'))
from bridge.core._core_data import garena_http_grant as http
from bridge.core._core_data import garena_tcp as tcp
from token_login import login_and_exchange, SsoLoginError


class Response(io.BytesIO):
    def __init__(self, body=b'', status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}

    def getcode(self):
        return self.status


class GrantTests(unittest.TestCase):
    def setUp(self):
        self.guards = [patch.object(socket, 'create_connection', side_effect=AssertionError('network forbidden')),
                       patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden')),
                       patch.object(urllib.request, 'urlopen', side_effect=AssertionError('HTTP forbidden'))]
        for guard in self.guards:
            guard.start()

    def tearDown(self):
        for guard in reversed(self.guards):
            guard.stop()

    def client(self, first=(141, b''), second=(141, b''), sso=None):
        client = tcp.GarenaTcpClient()
        client.uid = 123
        client.socket = Mock()
        client.socket.gettimeout.return_value = 15.0
        client.session_key = b'x' * 16
        if sso is None:
            sso = tcp._field_string(1, ' sso-SYNTHETIC ')  # Not 64 hex; no expiry.
        client._request_response = Mock(side_effect=[
            ({4: [439], 5: [first[0]]}, first[1]),
            ({4: [439], 5: [second[0]]}, second[1]),
            ({4: [442], 5: [0]}, sso),
        ])
        client.oauth_log = Mock()
        client.http_grant_opener = Mock(return_value=Response(
            b'{"access_token":"token-SYNTHETIC","open_id":"open-SYNTHETIC"}'))
        return client

    def send(self, obj=None, *, body=None, status=200, headers=None):
        response = Response(json.dumps(obj).encode() if body is None else body, status, headers)
        opener = Mock(return_value=response)
        return response, opener

    def test_full_pair_sso_http_success_same_session_no_third_oauth(self):
        client = self.client()
        out = client.oauth_token_login()
        self.assertEqual((out.uid, out.response_data, out.open_id), (123, 'token-SYNTHETIC', 'open-SYNTHETIC'))
        calls = client._request_response.call_args_list
        self.assertEqual([call.args[0] for call in calls], [439, 439, 442])
        self.assertEqual([tcp._first_int(tcp._parse_message(call.args[1]), 1) for call in calls[:2]], [100054, 100055])
        self.assertTrue(all(call.args[2] is client.session_key for call in calls))
        self.assertEqual(calls[2].args[1], b'')
        self.assertIn('deadline', calls[2].kwargs)
        client.socket.settimeout.assert_called_with(15.0)
        client.http_grant_opener.assert_called_once()
        self.assertEqual(client.oauth_diagnostics[1]['action'], 'sso-http-grant')
        logs = str(client.oauth_log.call_args_list) + str(client.oauth_diagnostics)
        for secret in ('token-SYNTHETIC', 'open-SYNTHETIC', 'sso-SYNTHETIC'):
            self.assertNotIn(secret, logs)

    def test_body_exact_denials_also_trigger_http(self):
        denied = (0, tcp._field_string(5, 'error_require_grant'))
        client = self.client(denied, denied)
        client.oauth_token_login()
        client.http_grant_opener.assert_called_once()

    def test_non_grant_second_error_never_fetches_sso_or_http(self):
        for rc, body in ((3, b''), (7, b''), (0, tcp._field_string(5, 'error_require_grant SECRET'))):
            client = self.client(second=(rc, body))
            with self.assertRaises(tcp.GarenaError):
                client.oauth_token_login()
            self.assertEqual(client._request_response.call_count, 2)
            client.http_grant_opener.assert_not_called()

    def test_direct_first_success_never_fetches_sso_or_http(self):
        body = tcp._field_string(1, 'open') + tcp._field_string(4, 'token')
        client = self.client(first=(0, body))
        client.oauth_token_login()
        self.assertEqual(client._request_response.call_count, 1)
        client.http_grant_opener.assert_not_called()

    def test_sso_failure_keeps141_and_no_http(self):
        for last in (tcp.GarenaError('SECRET'), ({5: [7]}, b''), ({5: [0]}, b''),
                     ({5: [0]}, tcp._field_string(1, ' ')), ({5: [0]}, b'\x0a\x10short')):
            client = self.client()
            client._request_response.side_effect = [({5: [141]}, b''), ({5: [141]}, b''), last]
            with self.assertRaises(tcp.GarenaError) as caught:
                client.oauth_token_login()
            self.assertEqual(caught.exception.code, 141)
            client.http_grant_opener.assert_not_called()
            client.socket.settimeout.assert_called_with(15.0)
            self.assertNotIn('SECRET', str(caught.exception) + str(client.oauth_log.call_args_list))

    def test_http_error_stops_no_more_tcp_requests(self):
        for obj, status, reason, code in (({'error': 'error_require_grant'}, 200, 'require_grant', 141),
                ({'error': 'error_too_many_requests'}, 200, 'rate_limited', 429),
                ({}, 429, 'rate_limited', 429), ({'error': 'SECRET'}, 403, 'http_rejected', None)):
            client = self.client()
            _, client.http_grant_opener = self.send(obj, status=status)
            with self.assertRaises(tcp.GarenaError) as caught:
                client.oauth_token_login()
            self.assertEqual((caught.exception.reason, caught.exception.code), (reason, code))
            self.assertEqual(client._request_response.call_count, 3)
            client.http_grant_opener.assert_called_once()
            self.assertNotIn('SECRET', str(caught.exception) + str(client.oauth_log.call_args_list))

    def test_exact_form_headers_and_timeout(self):
        response, opener = self.send({'access_token': 'token', 'open_id': 'open'})
        with patch.object(http.time, 'time_ns', return_value=1234567890000000):
            self.assertEqual(http.grant_token('sso-test', opener=opener), ('token', 'open'))
        req = opener.call_args.args[0]
        self.assertEqual(req.full_url, 'https://100055.connect.garena.com/oauth/token/grant')
        self.assertEqual(req.method, 'POST')
        self.assertEqual(urllib.parse.parse_qs(req.data.decode()), {
            'client_id': ['100055'], 'response_type': ['token'], 'redirect_uri': ['gop100055://'],
            'create_grant': ['true'], 'login_scenario': ['normal'], 'format': ['json'], 'id': ['1234567890']})
        headers = {key.lower(): value for key, value in req.header_items()}
        self.assertEqual(headers, {'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'accept': 'application/json, text/plain, */*',
            'user-agent': 'GarenaMSDK/5.12.1(SM-S918B ;Android 13;vi;vn;)',
            'origin': 'https://100055.connect.garena.com', 'cookie': 'sso_key=sso-test',
            'referer': 'https://100055.connect.garena.com/universal/oauth?locale=vi-VN&platform=1&response_type=token&login_scenario=normal&client_id=100055&redirect_uri=gop100055%3A%2F%2F'})
        self.assertEqual(opener.call_args.kwargs, {'timeout': 10.0})
        self.assertTrue(response.closed)

    def test_uri_query_fragment_precedence_and_escaping(self):
        for uri, expected in (
            (' gop100055://#access_token=t%2B1&openid=o%2F2 ', ('t+1', 'o/2')),
            ('gop100055://?access_token=query&openid=primary&open_id=other#access_token=fragment&openid=last', ('query', 'primary')),
            ('gop100055://?access_token=query#?access_token=fragment&open_id=oid', ('query', 'oid')),
            ('gop100055://?open_id=oid#access_token=t', ('t', 'oid')),
            ('http://[invalid', ('', ''))):
            self.assertEqual(http.extract_token_open_id(uri), expected)

    def test_redirect_http_errors_are_parsed_and_closed(self):
        for status in (301, 302, 303, 307):
            error = urllib.error.HTTPError('https://example.invalid', status, 'SECRET',
                {'Location': 'gop100055://#access_token=token&openid=open'}, io.BytesIO())
            opener = Mock(side_effect=error)
            self.assertEqual(http.grant_token('sso', opener=opener), ('token', 'open'))
            opener.assert_called_once()
            self.assertTrue(error.closed)

    def test_default_opener_disables_redirects(self):
        response, send = self.send({'access_token': 'token', 'open_id': 'open'})
        with patch.object(urllib.request, 'build_opener', return_value=Mock(open=send)) as build:
            http.grant_token('sso')
        self.assertIsInstance(build.call_args.args[0], http.NoRedirect)
        handler = build.call_args.args[0]
        self.assertIsNone(handler.redirect_request(None, None, 302, '', {}, 'http://example.invalid'))

    def test_json_alias_and_uri_fill_missing_only(self):
        for obj in ({'access_token': ' token ', 'openid': ' open '},
                    {'access_token': 'token', 'redirect_uri': 'gop100055://#access_token=ignored&open_id=open'},
                    {'open_id': 'open', 'redirect_uri': 'gop100055://?access_token=token&openid=ignored'}):
            _, opener = self.send(obj)
            self.assertEqual(http.grant_token('sso', opener=opener), ('token', 'open'))

    def test_explicit_throttle_precedes_token_like_body(self):
        _, opener = self.send({'access_token': 'token', 'open_id': 'open', 'error': 'error_too_many_requests'}, status=429)
        with self.assertRaises(tcp.GarenaError) as caught:
            http.grant_token('sso', opener=opener)
        self.assertEqual(caught.exception.reason, 'rate_limited')

    def test_gzip_and_limits(self):
        raw = b'{"access_token":"token","open_id":"open"}'
        _, opener = self.send(body=gzip.compress(raw), headers={'Content-Encoding': 'gzip'})
        self.assertEqual(http.grant_token('sso', opener=opener), ('token', 'open'))
        for body, headers in ((b'x' * (http.BODY_LIMIT + 1), {}),
                (gzip.compress(b'x' * (http.BODY_LIMIT + 1)), {'Content-Encoding': 'gzip'})):
            response, opener = self.send(body=body, headers=headers)
            with self.assertRaises(tcp.GarenaError) as caught:
                http.grant_token('sso', opener=opener)
            self.assertEqual(caught.exception.reason, 'response_too_large')
            self.assertTrue(response.closed)

    def test_invalid_replies_and_transport_never_leak(self):
        for body in (b'not json SECRET', b'[]', b'null', b'{"access_token":123,"open_id":"SECRET"}',
                     b'{"access_token":"SECRET"}', b'{"error":"error_require_grant SECRET"}'):
            response, opener = self.send(body=body)
            with self.assertRaises(tcp.GarenaError) as caught:
                http.grant_token('sso', opener=opener)
            self.assertNotEqual(caught.exception.code, 141)
            self.assertNotIn('SECRET', str(caught.exception))
            self.assertTrue(response.closed)
        opener = Mock(side_effect=urllib.error.URLError('SECRET cookie/token'))
        with self.assertRaises(tcp.GarenaError) as caught:
            http.grant_token('sso', opener=opener)
        self.assertEqual(caught.exception.reason, 'http_transport')
        self.assertNotIn('SECRET', str(caught.exception))
        opener.assert_called_once()

    def test_sso_cookie_rejects_header_injection(self):
        for key in ('', ' ', 'a\r\nSECRET', 'a;b', 'a\0b'):
            opener = Mock()
            with self.assertRaises(tcp.GarenaError):
                http.grant_token(key, opener=opener)
            opener.assert_not_called()

    def test_bundle_runs_new_flow_and_never_legacy_code_exchange(self):
        client = self.client()
        client.login = Mock(return_value=123)
        client.connect = Mock()
        client.oauth_login = Mock(side_effect=AssertionError('legacy flow'))
        client.get_sso_key = Mock(side_effect=AssertionError('legacy SSO'))
        opener = client.http_grant_opener
        bundle = login_and_exchange('synthetic', 'unused', 'device',
                                    tcp_client_factory=lambda **kw: client, opener=opener)
        self.assertEqual((bundle.access_token, bundle.open_id, bundle.sso_key),
                         ('token-SYNTHETIC', 'open-SYNTHETIC', ''))
        client.oauth_login.assert_not_called()
        client.get_sso_key.assert_not_called()
        opener.assert_called_once()

    def test_screening_http_failure_is_terminal_without_reauth(self):
        import uplv_engine
        engine = uplv_engine.Engine.__new__(uplv_engine.Engine)
        engine.login_lock, engine.last_login = threading.Lock(), 0
        authenticate = Mock(side_effect=SsoLoginError('V2 direct-token sanitized', code=429, stage='tcp-token-v2'))
        engine.runtime = (None, None, authenticate, lambda user: {'device_id':'unused'}, None, None)
        with patch('pve_runtime.loader.load') as load:
            result = engine.run({'accounts':[['synthetic','unused']], 'levels':[0],
                                 'targets':[12], 'screen_only':True}, threading.Event(), Mock(), Mock())
        self.assertFalse(result[0][0])
        authenticate.assert_called_once()
        load.assert_not_called()

    def test_bundle_http429_preserves_status_and_sanitizes(self):
        client = self.client()
        client.connect = Mock()
        client.login = Mock()
        _, opener = self.send({'error': 'SECRET'}, status=429)
        with self.assertRaises(SsoLoginError) as caught:
            login_and_exchange('synthetic', 'unused', 'device',
                               tcp_client_factory=lambda **kw: client, opener=opener)
        self.assertEqual((caught.exception.code, caught.exception.http_status), (429, 429))
        self.assertNotIn('SECRET', str(caught.exception))
        self.assertNotIn('141', str(caught.exception))
        opener.assert_called_once()

    def test_sso_uses_five_frame_match_bound_and_restores_timeout(self):
        client = self.client()
        client._request_response = tcp.GarenaTcpClient._request_response.__get__(client)
        client._next_id = Mock(return_value=123)
        wrong = tcp._field_varint(2, 999) + tcp._field_varint(3, 3) + tcp._field_varint(4, 442)
        frame = tcp._encrypt_payload(struct.pack('>H', len(wrong)) + wrong, client.session_key)
        client.socket.recv.side_effect = [struct.pack('<I', len(frame)), frame] * 5
        with self.assertRaises(tcp.GarenaError) as caught:
            client.request_sso_key_for_grant()
        self.assertEqual(caught.exception.reason, 'unmatched_response')
        self.assertEqual(client.socket.recv.call_count, 10)
        client.socket.sendall.assert_called_once()
        client.socket.settimeout.assert_called_with(15.)

    def test_sso_deadline_applies_to_send_and_chunk_reads(self):
        client = tcp.GarenaTcpClient()
        client.socket = Mock()
        client.socket.gettimeout.return_value = 15.0
        client.uid = 123
        client.session_key = b'x' * 16
        client._next_id = Mock(return_value=123)
        header = tcp._field_varint(2, 123) + tcp._field_varint(3, 3) + tcp._field_varint(4, 442)
        body = tcp._field_string(1, 'not-hex-no-expiry')
        encrypted = tcp._encrypt_payload(struct.pack('>H', len(header)) + header + body, client.session_key)
        client.socket.recv.side_effect = [struct.pack('<I', len(encrypted)), encrypted]
        with patch.object(tcp.time, 'monotonic', side_effect=[10., 10., 11., 12.]):
            self.assertEqual(client.request_sso_key_for_grant(), 'not-hex-no-expiry')
        self.assertEqual([call.args[0] for call in client.socket.settimeout.call_args_list], [8., 7., 6., 15.])
        _, payload = tcp._decode_packet(client.socket.sendall.call_args.args[0][4:], client.session_key)
        self.assertEqual(payload, b'')

    def test_sso_deadline_exhaustion_restores_socket_and_no_send(self):
        client = self.client()
        # Use real request machinery, but synthetic socket only.
        client._request_response = tcp.GarenaTcpClient._request_response.__get__(client)
        with patch.object(tcp.time, 'monotonic', side_effect=[10., 19.]):
            with self.assertRaises(tcp.GarenaError):
                client.request_sso_key_for_grant()
        client.socket.sendall.assert_not_called()
        client.socket.settimeout.assert_called_with(15.)


if __name__ == '__main__':
    unittest.main()
