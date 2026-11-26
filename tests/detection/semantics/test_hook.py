#!/usr/bin/env python3
"""test_hook.py - lab tests of roles/08-detection/files/auto-sec-login-hook.

No root. The hook is copied with its one path line pointing at a lab
queue, and run the way pam_exec runs it: a clean environment with only the
PAM_* names, stdin at end of file, through `timeout -s KILL 1`.

Usage: python3 test_hook.py [-v]
Prints one PASS or FAIL line per test; exit 1 when one fails.
"""
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
HOOK = os.path.join(REPO, "roles", "08-detection", "files", "auto-sec-login-hook")
PROFILE = os.path.join(REPO, "roles", "08-detection", "files", "auto-sec-login-alert")
PATH_LINE = "Q=/var/spool/auto-sec/events"
PAM = {"PAM_TYPE": "open_session", "PAM_SERVICE": "sshd", "PAM_USER": "root", "PAM_TTY": "ssh",
       "PAM_RHOST": "203.0.113.5", "PAM_RUSER": ""}


def fields(path):
    with open(path, "rb") as fh:
        data = fh.read()
    out = {}
    for part in data.split(b"\0"):
        if b"=" in part:
            k, v = part.split(b"=", 1)
            out[k.decode()] = v
    return out, data


class HookCase(unittest.TestCase):
    shell = None        # None: the hook's own #! line (/bin/sh)

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="hook-lab.")
        self.addCleanup(self.cleanup)
        self.queue = os.path.join(self.dir, "q")
        os.mkdir(self.queue, 0o700)
        with open(HOOK, encoding="utf-8") as fh:
            body = fh.read()
        self.assertEqual(body.count("\n" + PATH_LINE + "\n"), 1)
        self.hook = os.path.join(self.dir, "auto-sec-login-hook")
        with open(self.hook, "w", encoding="utf-8") as fh:
            fh.write(body.replace("\n" + PATH_LINE + "\n", "\nQ=" + self.queue + "\n"))
        os.chmod(self.hook, 0o700)

    def cleanup(self):
        os.chmod(self.queue, 0o700) if os.path.isdir(self.queue) else None
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_hook(self, env=None, wrap=True, preexec=None, path="/usr/bin:/bin"):
        """Returns (rc, seconds). env: only these names, as pam_exec passes them."""
        e = dict(PAM if env is None else env)
        if path is not None:
            e["PATH"] = path
        cmd = ([self.shell] if self.shell else []) + [self.hook]
        if wrap:
            cmd = ["/usr/bin/timeout", "-s", "KILL", "1"] + cmd
        t0 = time.monotonic()
        p = subprocess.run(cmd, env=e, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           preexec_fn=preexec, timeout=30)
        return p.returncode, time.monotonic() - t0

    def events(self):
        return sorted(n for n in os.listdir(self.queue))


class TestHook(HookCase):
    def test_one_small_file_with_the_login(self):
        """the event file: its name, its mode and every field"""
        rc, took = self.run_hook()
        self.assertEqual(rc, 0)
        self.assertLess(took, 1.0)
        names = self.events()
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"^h\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.ev$")
        path = os.path.join(self.queue, names[0])
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        f, data = fields(path)
        self.assertTrue(data.startswith(b"v=1\0src=hook\0"))
        self.assertTrue(data.endswith(b"\0end=1\0"))
        self.assertEqual(list(f), ["v", "src", "svc", "user", "ruser", "tty", "rhost", "app", "ruid", "ses", "auid", "end"])
        self.assertEqual((f["svc"], f["user"], f["tty"], f["rhost"], f["ruser"]), (b"sshd", b"root", b"ssh", b"203.0.113.5", b""))
        # the program that opened the session is this test (timeout's parent)
        self.assertEqual(f["app"], str(os.getpid()).encode())
        self.assertEqual(f["ruid"], str(os.getuid()).encode())
        self.assertRegex(f["ses"].decode(), r"^[0-9]*$")
        self.assertLess(len(data), 400)

    def test_only_when_a_session_opens(self):
        """nothing is written when a session closes, or outside PAM"""
        for typ in ("close_session", "auth", "account", ""):
            rc, _ = self.run_hook(dict(PAM, PAM_TYPE=typ))
            self.assertEqual(rc, 0)
        rc, _ = self.run_hook({})
        self.assertEqual(rc, 0)
        self.assertEqual(self.events(), [])

    def test_odd_values_stay_inside_their_field(self):
        """quotes, newlines and shell words in the PAM values"""
        evil_host = "evil\"host'\nsecond line; $(id) `id` \\ %s %n * ? ~ end=1"
        evil_user = "ro\"ot\n$(touch " + self.dir + "/pwned)"
        rc, _ = self.run_hook(dict(PAM, PAM_RHOST=evil_host, PAM_USER=evil_user, PAM_TTY="/dev/pts/9 x", PAM_RUSER="al'ice"))
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.events()), 1)
        f, data = fields(os.path.join(self.queue, self.events()[0]))
        self.assertEqual(f["rhost"], evil_host.encode())
        self.assertEqual(f["user"], evil_user.encode())
        self.assertEqual(f["tty"], b"/dev/pts/9 x")
        self.assertEqual(f["ruser"], b"al'ice")
        self.assertTrue(data.endswith(b"\0end=1\0"))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "pwned")))
        self.assertEqual(os.listdir(self.dir).count("pwned"), 0)

    def test_no_other_program_is_run(self):
        """with no PATH at all the hook still writes its file (shell builtins only)"""
        rc, _ = self.run_hook(path="/nonexistent")
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.events()), 1)
        f, _data = fields(os.path.join(self.queue, self.events()[0]))
        self.assertEqual(f["svc"], b"sshd")
        with open(HOOK, encoding="utf-8") as fh:
            code = [ln for ln in fh if not ln.lstrip().startswith("#")]
        for word in ("date", "mv ", "cat ", "sed ", "awk ", "logger", "curl", "flock", "sleep", "&\n", "$(", "`"):
            self.assertFalse(any(word in ln for ln in code), word)

    def test_queue_missing(self):
        """the queue folder is missing: exit 0, at once"""
        os.rmdir(self.queue)
        rc, took = self.run_hook()
        self.assertEqual(rc, 0)
        self.assertLess(took, 1.0)

    def test_queue_read_only(self):
        """the queue cannot be written: exit 0, at once"""
        if os.getuid() == 0:
            self.skipTest("root can write anywhere")
        os.chmod(self.queue, 0o500)
        rc, took = self.run_hook()
        self.assertEqual(rc, 0)
        self.assertLess(took, 1.0)
        self.assertEqual(self.events(), [])

    def test_queue_full(self):
        """the write fails (no space): exit 0, at once"""
        def no_space():
            # the write gets EFBIG, as it gets ENOSPC on a full disk
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        rc, took = self.run_hook(preexec=no_space)
        self.assertEqual(rc, 0)
        self.assertLess(took, 1.0)
        for n in self.events():
            self.assertEqual(os.path.getsize(os.path.join(self.queue, n)), 0)

    def test_queue_is_a_file(self):
        """the queue path is not a folder: exit 0"""
        os.rmdir(self.queue)
        with open(self.queue, "w") as fh:
            fh.write("x")
        rc, _ = self.run_hook()
        self.assertEqual(rc, 0)

    def test_no_proc(self):
        """without the /proc files it reads, it still writes the login"""
        # a copy that looks for /proc under a folder that is not there
        with open(self.hook, encoding="utf-8") as fh:
            body = fh.read().replace("/proc/", self.dir + "/noproc/")
        with open(self.hook, "w", encoding="utf-8") as fh:
            fh.write(body)
        rc, _ = self.run_hook()
        self.assertEqual(rc, 0)
        names = self.events()
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"^h\.[0-9]+-[0-9]+\.ev$")
        f, _data = fields(os.path.join(self.queue, names[0]))
        self.assertEqual((f["svc"], f["user"], f["ses"], f["ruid"]), (b"sshd", b"root", b"", b""))

    def test_many_logins_at_once(self):
        """50 hooks at the same moment: 50 whole files"""
        procs = [subprocess.Popen(["/usr/bin/timeout", "-s", "KILL", "1", self.hook], env=dict(PAM, PATH="/usr/bin:/bin"),
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                 for _ in range(50)]
        self.assertEqual([p.wait(timeout=30) for p in procs], [0] * 50)
        names = self.events()
        self.assertEqual(len(names), 50)
        for n in names:
            _f, data = fields(os.path.join(self.queue, n))
            self.assertTrue(data.endswith(b"\0end=1\0"))

    def test_a_hook_that_hangs_is_cut_off(self):
        """the PAM line's time limit: a hook that hangs costs one second"""
        with open(self.hook, "w") as fh:
            fh.write("#!/bin/sh\ntrap '' TERM INT HUP\nsleep 30\n")
        rc, took = self.run_hook()
        self.assertNotEqual(rc, 0)
        self.assertGreater(took, 0.9)
        self.assertLess(took, 2.0)


class TestHookBash(TestHook):
    """The same when /bin/sh is bash."""
    shell = "/bin/bash"

    def test_a_hook_that_hangs_is_cut_off(self):
        self.skipTest("the time limit does not depend on the shell")


class TestStatic(unittest.TestCase):
    def test_header_and_path_block(self):
        """the header line, and the one path line the tests rewrite"""
        with open(HOOK, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        self.assertEqual(lines[0], "#!/bin/sh")
        self.assertEqual(lines[1], "# Written by auto_sec (role 08). auto_sec changes this file only while this line is second.")
        a = lines.index("# --- path (tests rewrite this line) ---")
        b = lines.index("# --- end path ---")
        self.assertEqual(lines[a + 1:b], [PATH_LINE])
        self.assertEqual(lines[-2], "exit 0")
        self.assertFalse(any("AUTOSEC_" in ln for ln in lines))

    def test_profile(self):
        """the PAM profile: optional, interactive sessions only, off by default, a time limit"""
        with open(PROFILE, encoding="utf-8") as fh:
            text = fh.read()
        lines = text.split("\n")
        self.assertEqual(lines[0], "X-Written-By: auto_sec (role 08). auto_sec changes this file only while this line is first.")
        self.assertIn("Default: no", lines)
        self.assertIn("Session-Type: Additional", lines)
        self.assertIn("Session-Interactive-Only: yes", lines)
        self.assertNotIn(",", [ln for ln in lines if ln.startswith("Name: ")][0])
        mod = [ln for ln in lines if ln.startswith("\t")]
        self.assertEqual(mod, ["\toptional\tpam_exec.so quiet seteuid type=open_session /usr/bin/timeout -s KILL 1 "
                               "/usr/local/sbin/auto-sec-login-hook"])
        self.assertNotIn("end", mod[0].split("\t")[1] + mod[0].split("\t")[2].split(" ")[0])   # pam-auth-update replaces "end" there
        for field in ("Auth", "Account", "Password"):
            self.assertFalse(any(ln.startswith(field) for ln in lines), field)
        self.assertTrue(re.fullmatch(r"(?:[^\n]+\n)+", text))


class Lines(unittest.TextTestResult):
    """One PASS or FAIL line per test, like the other suites."""

    @staticmethod
    def _name(test):
        cls = test.id().split(".")[-2]
        who = {"TestHook": "hook", "TestHookBash": "hook-bash", "TestStatic": "static"}.get(cls, cls)
        return "%-9s %s" % (who, test.shortDescription() or "")

    def addSuccess(self, test):
        super().addSuccess(test)
        print("PASS  " + self._name(test), flush=True)

    def addFailure(self, test, err):
        super().addFailure(test, err)
        print("FAIL  " + self._name(test), flush=True)

    def addError(self, test, err):
        super().addError(test, err)
        print("FAIL  %s (error)" % self._name(test), flush=True)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        print("INFO  %s: not run here: %s" % (self._name(test), reason), flush=True)


if __name__ == "__main__":
    unittest.main(testRunner=unittest.TextTestRunner(resultclass=Lines, verbosity=0, stream=sys.stderr))
