import copy
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import requests
import main


def rule(domains, name="Blocked domains"):
    return {"name": name, "description": "keep", "enabled": True,
            "condition": {"domain_filter": {"list": domains}},
            "action": {"type": "reject"}}


class CliTests(unittest.TestCase):
    def run_cli(self, original, answers, *, expected=None, latest=None, final=None,
                put_status=200, put_error=None):
        expected = original if expected is None else expected
        states = [original, original if latest is None else latest,
                  expected if final is None else final]
        responses = [Mock(status_code=200, json=Mock(return_value={"rules": s})) for s in states]
        output = io.StringIO()
        with patch.object(main, "ORG_ID", "123"), patch.object(main, "OAUTH_TOKEN", "test"), \
                patch("builtins.input", side_effect=answers), \
                patch.object(main.requests, "get", side_effect=responses) as get, \
                patch.object(main.requests, "put", return_value=Mock(status_code=put_status),
                             side_effect=put_error) as put, redirect_stdout(output):
            code = main.main()
        return code, output.getvalue(), get, put

    def test_add_preserves_other_rules_and_options(self):
        other = {"name": "IP", "condition": {"ip_filter": {"list": ["127.0.0.1"]}},
                 "action": {"type": "accept", "options": {"force": "ham"}}, "enabled": False}
        original = [other, rule(["*.us"])]
        expected = copy.deepcopy(original)
        expected[1]["condition"]["domain_filter"]["list"].append("example.com")
        code, output, get, put = self.run_cli(original, ["Example.COM.", "1", "да"], expected=expected)
        self.assertEqual(code, 0)
        self.assertIn("Выполнено", output)
        self.assertEqual(get.call_count, 3)
        self.assertEqual(put.call_args.kwargs["json"], {"rules": expected})
        self.assertEqual(original[1]["condition"]["domain_filter"]["list"], ["*.us"])

    def test_remove_domain(self):
        expected = [rule(["*.us"])]
        code, output, _, put = self.run_cli([rule(["*.us", "example.com"])],
            ["example.com", "Удалить", "да"], expected=expected)
        self.assertEqual(code, 0)
        self.assertIn("удалён", output)
        self.assertEqual(put.call_args.kwargs["json"], {"rules": expected})

    def test_remove_last_domain(self):
        code, output, _, put = self.run_cli([rule(["*.us"])], ["*.us", "2", "да"], expected=[])
        self.assertEqual(code, 0)
        self.assertIn("последний домен", output)
        self.assertEqual(put.call_args.kwargs["json"], {"rules": []})

    def test_cancel_duplicate_missing_and_exit_never_write(self):
        for answers in [["example.com", "1", ""], ["*.us", "1"],
                        ["example.com", "2"], [""], ["example.com", "0"]]:
            with self.subTest(answers=answers):
                code, _, _, put = self.run_cli([rule(["*.us"])], answers)
                self.assertEqual(code, 0)
                put.assert_not_called()

    def test_select_blocking_rule(self):
        original = [rule(["*.us"]), rule(["example.org"], "Other block")]
        expected = copy.deepcopy(original)
        expected[1]["condition"]["domain_filter"]["list"].append("example.com")
        code, _, _, put = self.run_cli(original, ["2", "example.com", "1", "да"], expected=expected)
        self.assertEqual(code, 0)
        self.assertEqual(put.call_args.kwargs["json"], {"rules": expected})

    def test_allow_rule_is_not_selected(self):
        original = [rule(["allowed.org"], "Allow"), rule(["*.us"])]
        original[0]["action"] = {"type": "accept", "options": {"force": "ham"}}
        expected = copy.deepcopy(original)
        expected[1]["condition"]["domain_filter"]["list"].append("example.com")
        code, _, _, put = self.run_cli(original, ["example.com", "1", "да"], expected=expected)
        self.assertEqual(code, 0)
        self.assertEqual(put.call_args.kwargs["json"], {"rules": expected})

    def test_conflict_prevents_write(self):
        code, output, _, put = self.run_cli([rule(["*.us"])], ["example.com", "1", "да"], latest=[])
        self.assertEqual(code, 1)
        self.assertIn("изменились", output)
        put.assert_not_called()

    def test_http_failure_and_timeout_never_report_success(self):
        for kwargs in [{"put_status": 403}, {"put_error": requests.Timeout()}]:
            code, output, _, put = self.run_cli([rule(["*.us"])], ["example.com", "1", "да"], **kwargs)
            self.assertEqual(code, 1)
            self.assertNotIn("Выполнено", output)
            self.assertEqual(put.call_count, 1)

    def test_readback_mismatch_never_reports_success(self):
        code, output, _, _ = self.run_cli([rule(["*.us"])], ["example.com", "1", "да"], final=[])
        self.assertEqual(code, 1)
        self.assertNotIn("Выполнено", output)

    def test_invalid_api_shape_never_writes(self):
        with patch.object(main, "ORG_ID", "123"), patch.object(main, "OAUTH_TOKEN", "test"), \
                patch.object(main.requests, "get", return_value=Mock(status_code=200, json=lambda: {})), \
                patch.object(main.requests, "put") as put, redirect_stdout(io.StringIO()):
            self.assertEqual(main.main(), 1)
        put.assert_not_called()

    def test_normalize_and_reject_invalid_domains(self):
        self.assertEqual(main.normalize_domain("ПРИМЕР.РФ"), "xn--e1afmkfd.xn--p1ai")
        self.assertEqual(main.normalize_domain("*.us"), "*.us")
        for invalid in ["https://example.com", "a@example.com", "*", "a..com", "-a.com", "a b.com"]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                main.normalize_domain(invalid)

    def test_empty_rules_can_create_after_confirmation(self):
        code, _, _, put = self.run_cli([], ["example.com", "1", "нет"])
        self.assertEqual(code, 0)
        put.assert_not_called()
        with patch.object(main, "get_rules", side_effect=[[], [], [
                {"name": "Blocked domains", "description": "Домены, заблокированные через CLI",
                 "enabled": True, "condition": {"domain_filter": {"list": ["example.com"]}},
                 "action": {"type": "reject"}}]]), \
                patch.object(main, "ORG_ID", "123"), patch.object(main, "OAUTH_TOKEN", "test"), \
                patch("builtins.input", side_effect=["example.com", "1", "да"]), \
                patch.object(main.requests, "put", return_value=Mock(status_code=200)) as put, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(main.main(), 0)
            self.assertEqual(put.call_args.kwargs["json"]["rules"][0]["action"], {"type": "reject"})


if __name__ == "__main__":
    unittest.main()
