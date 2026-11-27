"""Production runtime web fallback and explicit-ban evidence regressions."""
import json
import struct
import unittest
from unittest.mock import Mock, patch

import test_uplv_oauth_v2 as oauth_tests
from bridge.core._core_data import garena_web_session as web
from bridge.core._core_data.garena_tcp import GarenaError
from token_login import login_and_exchange
from uplv_failure_policy import terminal_account_failure


class WebSessionTests(unittest.TestCase):
    def session(self, objects):
        replies=[]
        for obj in objects:
            reply=Mock(status_code=200)
            reply.raw.read.return_value=json.dumps(obj).encode()
            replies.append(reply)
        session=Mock(headers={})
        session.request.side_effect=replies
        return session,replies

    def test_tcp_pair_http_no_session_then_web_bundle(self):
        client=oauth_tests.GrantTests().client()
        client.connect=Mock();client.login=Mock()
        client.http_grant_opener=Mock(return_value=oauth_tests.Response(b'{"error":"error_no_session"}'))
        session,replies=self.session([dict(v1='a',v2='b'),dict(session_key='synthetic'),
            dict(redirect_uri='gop100055://'),dict(access_token='token',open_id='id')])
        with patch('socket.socket.connect',side_effect=AssertionError('network forbidden')):
            bundle=login_and_exchange('user','password','device',
                tcp_client_factory=lambda **kw:client,web_session_factory=lambda:session)
        self.assertEqual((bundle.access_token,bundle.open_id),('token','id'))
        self.assertEqual(client._request_response.call_count,3)
        self.assertEqual(session.request.call_count,4)
        for call in session.request.call_args_list:
            self.assertFalse(call.kwargs['allow_redirects'])
            self.assertTrue(call.kwargs['verify'])
        for reply in replies:reply.close.assert_called_once()
        session.close.assert_called_once()

    def test_captcha_otp_are_retryable_not_ban_and_do_not_continue_login(self):
        for error in ('error_require_captcha','error_require_otp','error_invalid_password'):
            session,replies=self.session([dict(error=error)])
            with self.assertRaises(GarenaError) as caught:
                web.web_login_grant('user','password',session_factory=lambda:session)
            self.assertEqual(terminal_account_failure(dict(final_error=str(caught.exception))), '')
            self.assertEqual(session.request.call_count,1)
            session.close.assert_called_once()

    def test_1042_server_message_reaches_terminal_ban_policy(self):
        from purepc.purepc_run import _pump_state
        reason='Hệ thống phát hiện bạn dùng APK đã chỉnh sửa'.encode()+b'\0'
        full=struct.pack('>IBII',91126,0,99,len(reason))+reason+b'unknown'
        state={'csids':set(),'read_only_v2':True}
        with patch('purepc.uplevel_stateful.read_frames',return_value=[dict(csid=1042,body_full=full.hex())]):
            _pump_state(None,None,0,state)
        self.assertEqual(state['login_limit']['unparsed_tail_bytes'],7)
        self.assertEqual(terminal_account_failure(dict(final_error=state['reject'])),'restricted')


if __name__=='__main__':unittest.main()
