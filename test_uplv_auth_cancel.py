"""Offline cooperative auth cancellation; no live credentials or network."""
import io
import json
from pathlib import Path
import struct
import sys
import threading
import unittest
import urllib.error
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent / 'uplv_runtime/pve_backend'))
from bridge.core._core_data import garena_http_grant as http
from bridge.core._core_data import garena_tcp as tcp
from bridge.core._core_data import garena_web_session as web
from token_login import login_and_exchange


class Response(io.BytesIO):
    def __init__(self, obj, status=200, headers=None):
        super().__init__(json.dumps(obj).encode())
        self.headers = headers or {}
        self.status = status

    def getcode(self):
        return self.status


class AuthCancelTests(unittest.TestCase):
    def setUp(self):
        self.stop = threading.Event()
        for target in ('socket.create_connection', 'socket.socket.connect',
                       'urllib.request.urlopen', 'urllib.request.OpenerDirector.open',
                       'requests.sessions.Session.request'):
            guard = patch(target, side_effect=AssertionError('network forbidden'))
            guard.start()
            self.addCleanup(guard.stop)

    def stopped(self):
        return self.assertRaisesRegex(tcp.AuthStopped, '^Stopped$')

    def client(self):
        client = tcp.GarenaTcpClient()
        client.socket = Mock()
        client.socket.gettimeout.return_value = 20.0
        client.session_key = b'x' * 16
        client.uid = 123
        client.stop_event = self.stop
        client.connect = Mock()
        client.login = Mock()
        return client

    def grant_client(self):
        client = self.client()
        client._request_response = Mock(side_effect=[
            ({4: [439], 5: [141]}, b''),
            ({4: [439], 5: [141]}, b''),
            ({4: [442], 5: [0]}, tcp._field_string(1, 'synthetic-sso')),
        ])
        return client

    def login(self, client, **kwargs):
        return login_and_exchange('fixture', 'unused', 'device',
            tcp_client_factory=lambda **kw: client, stop_event=self.stop, **kwargs)

    def session(self, objects):
        replies = []
        for obj in objects:
            reply = Mock(status_code=200, headers={})
            reply.raw.read.return_value = json.dumps(obj).encode()
            replies.append(reply)
        session = Mock(headers={})
        session.request.side_effect = replies
        return session, replies

    def test_preexisting_stop_never_constructs_or_connects(self):
        self.stop.set()
        factory = Mock()
        with self.stopped():
            login_and_exchange('fixture', 'unused', 'device',
                tcp_client_factory=factory, stop_event=self.stop)
        factory.assert_not_called()

    def test_hook_is_installed_before_enter_connect(self):
        client = tcp.GarenaTcpClient()
        def factory(**kwargs):
            self.stop.set()
            return client
        with self.stopped():
            login_and_exchange('fixture', 'unused', 'device',
                tcp_client_factory=factory, stop_event=self.stop)
        self.assertIs(client.stop_event, self.stop)
        self.assertIsNone(client.socket)

    def test_stop_after_connect_closes_socket_when_enter_raises(self):
        client = tcp.GarenaTcpClient()
        client.stop_event = self.stop
        sock = Mock()
        def connect(*args):
            self.stop.set()
            return sock
        with patch.object(tcp.socket, 'create_connection', side_effect=connect) as send:
            with self.stopped():
                with client:
                    self.fail('Stopped connect entered context')
        send.assert_called_once()
        sock.close.assert_called_once()
        self.assertIsNone(client.socket)

    def test_stop_after_failed_connect_prevents_another_endpoint(self):
        client = tcp.GarenaTcpClient()
        client.stop_event = self.stop
        def connect(*args):
            self.stop.set()
            raise OSError('synthetic')
        with patch.object(tcp.socket, 'create_connection', side_effect=connect) as send:
            with self.stopped():
                client.connect()
        send.assert_called_once()

    def test_stop_after_tcp_login_prevents_oauth_and_closes_socket(self):
        client = self.client()
        sock = client.socket
        client.login.side_effect = lambda *args: self.stop.set()
        client.oauth_token_login = Mock()
        with self.stopped():
            self.login(client)
        client.oauth_token_login.assert_not_called()
        sock.close.assert_called_once()

    def test_stop_before_send_sends_nothing(self):
        client = self.client()
        self.stop.set()
        with self.stopped():
            client._request_response(439, b'')
        client.socket.sendall.assert_not_called()

    def test_stop_after_send_prevents_receive(self):
        client = self.client()
        client.socket.sendall.side_effect = lambda *args: self.stop.set()
        with self.stopped():
            client._request_response(439, b'')
        client.socket.recv.assert_not_called()

    def test_stop_after_partial_receive_prevents_next_receive(self):
        client = self.client()
        def receive(*args):
            self.stop.set()
            return b'x'
        client.socket.recv.side_effect = receive
        with self.stopped():
            client._receive_exact(4)
        client.socket.recv.assert_called_once()

    def test_stop_after_frame_header_prevents_body_receive(self):
        client = self.client()
        def receive(*args):
            self.stop.set()
            return struct.pack('<I', 12)
        client.socket.recv.side_effect = receive
        with self.stopped():
            client._request_response(439, b'')
        client.socket.recv.assert_called_once()

    def test_stop_at_oauth_fallback_prevents_second_oauth(self):
        client = self.grant_client()
        client.oauth_log = lambda message: self.stop.set()
        with self.stopped():
            client.oauth_token_login()
        client._request_response.assert_called_once()

    def test_stop_after_sso_prevents_http_grant(self):
        client = self.grant_client()
        client.oauth_log = lambda message: self.stop.set() if '[sso-v2]' in message else None
        opener = Mock()
        with self.stopped():
            self.login(client, opener=opener, progress=client.oauth_log)
        self.assertEqual(client._request_response.call_count, 3)
        opener.assert_not_called()

    def test_sso_cancellation_is_not_wrapped_and_restores_timeout(self):
        client = self.client()
        sock = client.socket
        def response(*args, **kwargs):
            self.stop.set()
            return {5: [0]}, tcp._field_string(1, 'synthetic')
        client._request_response = Mock(side_effect=response)
        with self.stopped():
            client.request_sso_key_for_grant()
        sock.settimeout.assert_called_with(20.0)

    def test_http_preexisting_stop_never_sends(self):
        self.stop.set()
        opener = Mock()
        with self.stopped():
            http.grant_token('synthetic', opener=opener, stop_event=self.stop)
        opener.assert_not_called()

    def test_http_stop_after_response_prevents_web_fallback_and_closes_resources(self):
        for http_error in (False, True):
            with self.subTest(http_error=http_error):
                self.stop.clear()
                client = self.grant_client()
                sock = client.socket
                response = Response({'error': 'error_no_session'})
                if http_error:
                    response = urllib.error.HTTPError('https://example.invalid', 200,
                        'synthetic', {}, response)
                def send(*args, **kwargs):
                    self.stop.set()
                    if http_error:
                        raise response
                    return response
                opener = Mock(side_effect=send)
                factory = Mock()
                with self.stopped():
                    self.login(client, opener=opener, web_session_factory=factory)
                opener.assert_called_once()
                factory.assert_not_called()
                self.assertTrue(response.closed)
                sock.close.assert_called_once()

    def test_http_stop_during_body_read_does_not_return_token(self):
        response = Response({'access_token': 'synthetic', 'open_id': 'synthetic'})
        original_read = response.read
        def read(*args):
            self.stop.set()
            return original_read(*args)
        response.read = read
        with self.stopped():
            http.grant_token('synthetic', opener=Mock(return_value=response), stop_event=self.stop)
        self.assertTrue(response.closed)

    def test_web_stop_between_prelogin_and_login_closes_response_and_session(self):
        session, replies = self.session([dict(v1='a', v2='b')])
        with patch.object(web, 'transform_password') as transform:
            with self.stopped():
                web.web_login_grant('fixture', 'unused', session_factory=lambda: session,
                    progress=lambda message: self.stop.set(), stop_event=self.stop)
        transform.assert_not_called()
        session.request.assert_called_once()
        replies[0].close.assert_called_once()
        session.close.assert_called_once()

    def test_web_stop_after_response_does_not_read_body(self):
        session, replies = self.session([{}])
        def request(*args, **kwargs):
            self.stop.set()
            return replies[0]
        session.request.side_effect = request
        with self.stopped():
            web.web_login_grant('fixture', 'unused', session_factory=lambda: session,
                                stop_event=self.stop)
        replies[0].raw.read.assert_not_called()
        replies[0].close.assert_called_once()
        session.close.assert_called_once()

    def test_web_stop_during_read_prevents_next_request(self):
        session, replies = self.session([dict(v1='a', v2='b')])
        def read(*args, **kwargs):
            self.stop.set()
            return b'{"v1":"a","v2":"b"}'
        replies[0].raw.read.side_effect = read
        with self.stopped():
            web.web_login_grant('fixture', 'unused', session_factory=lambda: session,
                                stop_event=self.stop)
        session.request.assert_called_once()
        replies[0].close.assert_called_once()
        session.close.assert_called_once()

    def test_web_preexisting_stop_never_creates_session(self):
        self.stop.set()
        factory = Mock()
        with self.stopped():
            web.web_login_grant('fixture', 'unused', session_factory=factory,
                                stop_event=self.stop)
        factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
