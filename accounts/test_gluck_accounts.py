"""Defends: the generated password never appears in a child process's argv.

/proc on spain has no hidepid and /proc/<pid>/cmdline is readable across uids,
so a password on argv is readable by every local account for the life of the
child. These tests run the real set_password against a stub binary that reports
its own argv back, so the assertion is about the shipped code path and not a
mock of it.
"""

import os
import sys
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

os.environ.setdefault("LLDAP_PASSWORD_FILE", "/dev/null")

import gluck_accounts  # noqa: E402


def _stub(exit_code=0, echo=""):
    """A stub lldap_set_password that reports argv and env, then exits."""
    d = tempfile.mkdtemp()
    out = os.path.join(d, "report.json")
    script = os.path.join(d, "lldap_set_password")
    Path(script).write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json, os, sys
            json.dump(
                {{"argv": sys.argv, "env": os.environ.get("LLDAP_USER_PASSWORD")}},
                open({out!r}, "w"),
            )
            sys.stderr.write({echo!r})
            sys.exit({exit_code})
            """
        )
    )
    os.chmod(script, 0o755)
    return script, out


class SetPasswordArgv(unittest.TestCase):
    def test_password_reaches_the_child_but_not_its_argv(self):
        script, out = _stub()
        gluck_accounts.SET_PASSWORD_BIN = script
        gluck_accounts.set_password("tok-abc", "alice", "s3cret-passphrase")

        report = json.loads(Path(out).read_text())
        self.assertEqual(report["env"], "s3cret-passphrase")
        self.assertNotIn("s3cret-passphrase", " ".join(report["argv"]))
        self.assertNotIn("--password", report["argv"])
        self.assertIn("alice", report["argv"])

    def test_negative_control_the_assertion_can_fail(self):
        """A stub told to take --password proves the argv check is live."""
        script, out = _stub()
        gluck_accounts.SET_PASSWORD_BIN = script
        import subprocess

        subprocess.run([script, "--password", "s3cret-passphrase"], check=True)
        report = json.loads(Path(out).read_text())
        self.assertIn("s3cret-passphrase", " ".join(report["argv"]))

    def test_failure_scrubs_the_password_out_of_the_diagnosis(self):
        script, _ = _stub(exit_code=3, echo="rejected password s3cret-passphrase\n")
        gluck_accounts.SET_PASSWORD_BIN = script
        with self.assertRaises(gluck_accounts.SetPasswordError) as cm:
            gluck_accounts.set_password("tok-abc", "alice", "s3cret-passphrase")
        message = str(cm.exception)
        self.assertNotIn("s3cret-passphrase", message)
        self.assertIn("***", message)
        self.assertIn("rc=3", message)

    def test_failure_raises_rather_than_returning_quietly(self):
        script, _ = _stub(exit_code=1)
        gluck_accounts.SET_PASSWORD_BIN = script
        with self.assertRaises(gluck_accounts.SetPasswordError):
            gluck_accounts.set_password("tok-abc", "alice", "pw")


if __name__ == "__main__":
    unittest.main(verbosity=2)
