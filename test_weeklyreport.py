import unittest
from unittest.mock import Mock

from weeklyreport import OAUTH_PARAMS, PROFILE_URL, WEEKLY_URL, fetch_weekly_profile


class WeeklyReportTests(unittest.TestCase):
    def session(self, init=None, grant=None):
        session = Mock()
        session._api_url.return_value = "https://auth.garena.com/api/universal/oauth"
        session.request.side_effect = [
            init or (200, "", "application/json", {"sso_session": {"login": True}}),
            grant or (200, "", "application/json", {"redirect_uri": WEEKLY_URL + "?code=test-code"}),
        ]
        session.api_result.return_value = {"ok": True, "status": 200, "body": {"player": {"name": "sample"}}}
        return session

    def test_code_is_granted_for_weekly_and_sent_as_code_header(self):
        session = self.session()
        result = fetch_weekly_profile(session)
        self.assertTrue(result["ok"])
        session._api_url.assert_called_once_with("auth.garena.com", "/api/universal/oauth", OAUTH_PARAMS)
        grant = session.request.call_args_list[1].kwargs["form_body"]
        self.assertEqual(grant["redirect_uri"], WEEKLY_URL)
        self.assertEqual(grant["response_type"], "code")
        session.api_result.assert_called_once_with(
            PROFILE_URL,
            headers={"Code": "test-code", "Partition": "1011", "Referer": WEEKLY_URL},
        )
        self.assertNotIn("test-code", repr(result))

    def test_tcp_without_web_session_is_not_treated_as_web_login(self):
        session = self.session(init=(200, "", "", {"sso_session": {"login": False}}))
        self.assertEqual(fetch_weekly_profile(session)["error"], "web_login_required")
        self.assertEqual(session.request.call_count, 1)
        session.api_result.assert_not_called()

    def test_rate_limit_stops_without_retry(self):
        for stage in ("init", "grant"):
            with self.subTest(stage=stage):
                session = self.session(**{stage: (429, "", "", {"error": "error_too_many_requests"})})
                self.assertEqual(fetch_weekly_profile(session)["status"], 429)
                session.api_result.assert_not_called()
                self.assertEqual(session.request.call_count, 1 if stage == "init" else 2)

    def test_wrong_or_missing_code_is_not_sent_to_profile(self):
        for callback in (
            "https://kientuong.lienquan.garena.vn/?code=secret",
            "https://weeklyreport.moba.garena.vn.evil.invalid/?code=secret",
            WEEKLY_URL + "?access_token=secret",
            WEEKLY_URL + "?code=a&code=b",
        ):
            with self.subTest(callback=callback):
                session = self.session(grant=(200, "", "", {"redirect_uri": callback}))
                result = fetch_weekly_profile(session)
                self.assertFalse(result["ok"])
                self.assertNotIn("secret", repr(result))
                session.api_result.assert_not_called()

    def test_application_failure_is_preserved(self):
        session = self.session()
        session.api_result.return_value = {"ok": False, "status": 200, "body": {"error": "ERROR__GOP_LOGIN_FAILED"}}
        self.assertFalse(fetch_weekly_profile(session)["ok"])

    def test_network_exception_does_not_leak_callback(self):
        session = self.session()
        session.request.side_effect = RuntimeError("https://example.invalid/?code=secret")
        result = fetch_weekly_profile(session)
        self.assertEqual(result["error"], "RuntimeError")
        self.assertNotIn("secret", repr(result))

    def test_optional_weekly_failure_does_not_invalidate_kientuong(self):
        from garena_api_test_chrome1 import result_rate_limit_suspected
        result = {"apis": {"kientuong_player": {"ok": True, "status": 200}},
                  "optional_apis": {"weekly_profile": {"status": 429, "error": "error_too_many_requests"}}}
        self.assertFalse(result_rate_limit_suspected(result))
        result["apis"]["kientuong_player"]["status"] = 429
        self.assertTrue(result_rate_limit_suspected(result))


if __name__ == "__main__":
    unittest.main()
