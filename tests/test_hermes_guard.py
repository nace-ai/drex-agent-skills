"""Offline regression checks for Hermes v0.23.0's environment-access guard."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
# Copied verbatim from Hermes Agent v0.23.0, tools/skills_guard.py,
# THREAT_PATTERNS (skills-guard-v10), inspected at:
# /tmp/orch/nac2-98/hermes-agent/tools/skills_guard.py
# Upstream: https://github.com/NousResearch/hermes-agent/blob/v0.23.0/tools/skills_guard.py
# _determine_verdict: critical -> dangerous, high -> caution, medium/low -> safe.
# INSTALL_POLICY: community allows safe only. Keep ordinary credential reads
# visible as MEDIUM; copying/iterating the whole environment is HIGH.
ENV_PATTERNS = (
    (r'^[^#\n]*os\.environ\b(?!\s*\.get\s*\()', "python_os_environ", "high"),
    (r'os\.environ\s*\.get\s*\(\s*["\'][^"\']*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)',
     "python_environ_get_secret", "medium"),
    (r'os\.getenv\s*\(\s*[^\)]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)',
     "python_getenv_secret", "medium"),
)


def env_findings(text):
    return [(pattern_id, severity) for pattern, pattern_id, severity in ENV_PATTERNS
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE)]


class HermesGuardTests(unittest.TestCase):
    def test_guard_detects_previous_environment_copy_regression(self):
        self.assertIn(("python_os_environ", "high"),
                      env_findings('env = dict(os.environ, DREX_API_KEY=key)'))
        self.assertEqual(env_findings('key = os.environ.get("DREX_API_KEY")'),
                         [("python_environ_get_secret", "medium")])

    def test_bundled_helper_and_root_shim_have_no_high_environment_findings(self):
        for relative in ("skills/drex-for-harness/scripts/drex.py", "scripts/drex.py"):
            with self.subTest(path=relative):
                findings = env_findings((ROOT / relative).read_text(encoding="utf-8"))
                self.assertFalse([item for item in findings if item[1] == "high"], findings)
