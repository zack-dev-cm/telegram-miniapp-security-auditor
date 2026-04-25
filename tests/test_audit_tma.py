from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from skill.telegram_miniapp_security_auditor_import import load_auditor


audit_tma = load_auditor()


class TelegramMiniAppSecurityAuditTests(unittest.TestCase):
    def test_full_project_with_validator_passes_static_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.js").write_text(
                "const initData = window.Telegram.WebApp.initData;\n"
                "fetch('/api/hire-requests', {method:'POST', body: initData});\n",
                encoding="utf-8",
            )
            (root / "server.py").write_text(
                "import hmac, hashlib, time\n"
                "def validate_init_data(init_data, bot_token):\n"
                "    secret_key = hmac.new(b'WebAppData', bot_token.encode(), hashlib.sha256).digest()\n"
                "    computed_hash = hmac.new(secret_key, b'auth_date=1', hashlib.sha256).hexdigest()\n"
                "    hmac.compare_digest(computed_hash, 'x')\n"
                "    auth_date = 1\n"
                "    max_age_sec = 86400\n"
                "    if time.time() - auth_date > max_age_sec: raise ValueError('too old')\n"
                "def brief_policy(brief):\n"
                "    if 'brief_contains_email' in brief: raise ValueError('brief_contains_email')\n"
                "@app.get('/healthz')\n"
                "def healthz(): return {'ok': True}\n",
                encoding="utf-8",
            )
            report = audit_tma.audit(root)
            self.assertNotEqual(report["decision"], "BLOCK")

    def test_frontend_only_blocks_missing_server_validation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "index.html").write_text(
                '<script src="https://telegram.org/js/telegram-web-app.js"></script>',
                encoding="utf-8",
            )
            (root / "app.js").write_text(
                "const initData = window.Telegram.WebApp.initData; document.body.innerHTML = 'ok';",
                encoding="utf-8",
            )
            report = audit_tma.audit(root)
            self.assertEqual(report["decision"], "BLOCK")
            rule_ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("initdata-no-server-validation", rule_ids)

    def test_realistic_token_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "server.py").write_text(
                "TELEGRAM_BOT_TOKEN='9876543210:abcDEF_1234567890abcDEF_1234567890abcDEF_1234567890'\n",
                encoding="utf-8",
            )
            report = audit_tma.audit(root)
            self.assertEqual(report["decision"], "BLOCK")
            rule_ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("hardcoded-telegram-token", rule_ids)

    def test_placeholder_token_is_review_not_block(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "test_report.md").write_text(
                "example token 1234567:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi\n",
                encoding="utf-8",
            )
            report = audit_tma.audit(root)
            rule_ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("placeholder-telegram-token", rule_ids)
            self.assertNotIn("hardcoded-telegram-token", rule_ids)


if __name__ == "__main__":
    unittest.main()
