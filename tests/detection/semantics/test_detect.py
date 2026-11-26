#!/usr/bin/env python3
"""test_detect.py - lab tests of roles/08-detection/files/auto-sec-detect.

No root, no network beyond 127.0.0.1, never the real Telegram: messages
go to tests/detection/fake_telegram.py or to a list in memory.

Usage: python3 test_detect.py [-v] [TestName ...]
The program under test is loaded from the repository (../../../roles/...).
Every test gets its own lab root; the program runs with --root <lab>, so
its queue, state, settings, PAM file and the systemctl/journalctl stubs
are all in there.
"""
import importlib.machinery
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
PROGRAM = os.path.join(REPO, "roles", "08-detection", "files", "auto-sec-detect")
FAKE = os.path.join(REPO, "tests", "detection", "fake_telegram.py")
FIXTURES = os.path.join(HERE, "fixtures", "journal-lines.txt")
TOKEN = "12345678:TEST-TOKEN-ONLY-for-the-fake-sink"
QUIET_FP = "SHA256:91kTeUIf2aJCD8UWjmPB35/8mOW3iviwpjZ8Yz+JXR8"
OTHER_FP = "SHA256:kYCVg3P00Hi90avKsg7gku5eBXW1oNQSGxCAndEHFOQ"

_loader = importlib.machinery.SourceFileLoader("auto_sec_detect", PROGRAM)
_spec = importlib.util.spec_from_loader("auto_sec_detect", _loader)
mod = importlib.util.module_from_spec(_spec)
_loader.exec_module(mod)

SYSTEMCTL_STUB = """#!/bin/sh
# lab stub: answers from <lab>/stub/states ("<unit> <state>"; not listed = active)
d=$(dirname "$0")
case $1 in
  is-system-running) cat "$d/system" 2>/dev/null || echo running; exit 0 ;;
  is-active)
    st=active
    while read -r u s; do [ "$u" = "$2" ] && st=$s; done < "$d/states"
    echo "$st"; [ "$st" = active ]; exit $? ;;
esac
exit 1
"""
JOURNALCTL_STUB = """#!/bin/sh
# lab stub: prints <lab>/stub/journal.out, then stays (or ends at once)
d=$(dirname "$0")
printf '%s\\n' "$*" >> "$d/journal.args"
[ -e "$d/journal.exit" ] && exit 1
cat "$d/journal.out" 2>/dev/null
exec sleep 600
"""


def utc(t):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t))


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class Clock:
    def __init__(self):
        self.t = 1795000000.0

    def __call__(self):
        return self.t


class Lab:
    """One lab root: settings, queue, state, stubs."""

    def __init__(self, quiet_accounts="auditor cve-patcher", quiet_keys=QUIET_FP, login_hook="true", api=""):
        self.root = tempfile.mkdtemp(prefix="detect-lab.")
        for d in ("etc/auto-sec", "var/spool/auto-sec/events", "var/lib/auto-sec/detect", "stub",
                  "etc/pam.d", "usr/share/pam-configs", "usr/local/sbin", "run/auto-sec", "proc/sys/kernel/random"):
            os.makedirs(os.path.join(self.root, d))
        self.queue = os.path.join(self.root, "var/spool/auto-sec/events")
        self.state_dir = os.path.join(self.root, "var/lib/auto-sec/detect")
        self.write_conf(quiet_accounts, quiet_keys, login_hook, api)
        for name, body in (("systemctl", SYSTEMCTL_STUB), ("journalctl", JOURNALCTL_STUB)):
            p = os.path.join(self.root, "stub", name)
            with open(p, "w", encoding="ascii") as fh:
                fh.write(body)
            os.chmod(p, 0o755)
        open(os.path.join(self.root, "stub/states"), "w").close()
        with open(os.path.join(self.root, "proc/sys/kernel/random/boot_id"), "w") as fh:
            fh.write("11111111-2222-3333-4444-555555555555\n")
        self.pam_ok()
        mod.ROOT = self.root
        self.clock = Clock()
        self.sent = []
        self.answers = []      # what the next sends return; empty = ok
        self.n = 0

    def write_conf(self, quiet_accounts, quiet_keys, login_hook, api, token=TOKEN):
        with open(os.path.join(self.root, "etc/auto-sec/detect.conf"), "w", encoding="utf-8") as fh:
            fh.write("[detect]\nhost_label = lab-host\ntelegram_bot_token = %s\ntelegram_chat_id = -100123\n"
                     "quiet_accounts = %s\nquiet_ssh_keys = %s\nalive_time = 09:00\nlogin_hook = %s\n%s"
                     % (token, quiet_accounts, quiet_keys, login_hook, ("api_base = %s\n" % api) if api else ""))

    def pam_ok(self):
        with open(os.path.join(self.root, "etc/pam.d/common-session"), "w") as fh:
            fh.write("session\trequired\tpam_unix.so \n" + mod.PAM_LINE + "\n# end of pam-auth-update config\n")
        with open(os.path.join(self.root, "usr/share/pam-configs/auto-sec-login-alert"), "w") as fh:
            fh.write(mod.PROFILE_HEADER + "\nName: x\n")
        hook = os.path.join(self.root, "usr/local/sbin/auto-sec-login-hook")
        with open(hook, "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(hook, 0o700)

    def close(self):
        mod.ROOT = ""
        shutil.rmtree(self.root, ignore_errors=True)

    def fake_send(self, text):
        if self.answers:
            ans = self.answers.pop(0)
            if ans is not True:
                return False, ans
        self.n += 1
        self.sent.append(text)
        return True, self.n

    def sender(self):
        return mod.Sender(mod.load_conf(), now=self.clock, send=self.fake_send)

    def hook(self, svc, user, app, ruser="", tty="", rhost="", ruid="", complete=True, raw=None):
        """An event file exactly as the login hook writes it."""
        self.n_ev = getattr(self, "n_ev", 0) + 1
        path = os.path.join(self.queue, "h.aaaaaaaa-%04d.ev" % self.n_ev)
        if raw is None:
            raw = b"v=1\0src=hook\0" + b"".join(
                ("%s=%s" % (k, v)).encode() + b"\0" for k, v in (
                    ("svc", svc), ("user", user), ("ruser", ruser), ("tty", tty), ("rhost", rhost),
                    ("app", app), ("ruid", ruid), ("ses", "4294967295"), ("auid", "4294967295")))
            if complete:
                raw += b"end=1\0"
        with open(path, "wb") as fh:
            fh.write(raw)
        os.utime(path, (self.clock.t, self.clock.t))
        return path

    def journal(self, kind, app, **fields):
        f = {"src": "journal", "kind": kind, "app": app, "ts": str(int(self.clock.t))}
        f.update(fields)
        assert mod.write_event("j", f)

    def step(self, s, seconds=0.0):
        """Advance the lab clock and let the sender work once."""
        self.clock.t += seconds
        s.scan()
        s.ripe()
        s.flush()

    def drain(self, s, seconds, tick=0.5):
        end = self.clock.t + seconds
        self.step(s)
        while self.clock.t < end:
            self.step(s, tick)


class Base(unittest.TestCase):
    lab_args = {}

    def setUp(self):
        self.lab = Lab(**self.lab_args)
        self.addCleanup(self.lab.close)


class TestReader(Base):
    def test_fixture_lines(self):
        n = hits = 0
        sets = set()
        with open(FIXTURES, encoding="utf-8") as fh:
            for raw in fh:
                if not raw.strip() or raw.startswith("#"):
                    continue
                fx = json.loads(raw)
                n += 1
                sets.update(fx["sets"])
                got = mod.journal_record(fx["rec"])
                if fx["want"] is None:
                    self.assertIsNone(got, fx["rec"]["MESSAGE"])
                    continue
                hits += 1
                self.assertIsNotNone(got, fx["rec"]["MESSAGE"])
                self.assertEqual(got["src"], "journal")
                for k, v in fx["want"].items():
                    self.assertEqual(got.get(k, ""), v, "%s of %r" % (k, fx["rec"]["MESSAGE"]))
        self.assertGreaterEqual(n, 40)
        self.assertGreaterEqual(hits, 25)
        self.assertEqual(sets, {"jammy", "noble", "resolute", "bookworm", "trixie"})

    def test_sudo_shell_rule(self):
        def is_shell(cmd):
            return mod.parse_sudo("  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=" + cmd) is not None
        for cmd in ("/bin/bash", "/usr/bin/zsh", "/bin/sh -l", "/usr/bin/su", "/usr/bin/su - postgres", "/usr/bin/sudo -s",
                    "/bin/bash --login"):
            self.assertTrue(is_shell(cmd), cmd)
        for cmd in ("/bin/sh -c id", "/bin/bash -lc 'apt update'", "/bin/bash /root/x.sh", "/usr/bin/su -c id postgres",
                    "/usr/bin/su postgres --command=id", "/usr/bin/systemctl restart nginx", "/usr/bin/vim /etc/hosts"):
            self.assertFalse(is_shell(cmd), cmd)

    def test_journal_args(self):
        a = mod.journal_args("")
        self.assertEqual(a[0], self.lab.root + "/stub/journalctl")
        for word in ("--follow", "--output=json", "--lines=0", "_EXE=/usr/sbin/sshd", "_EXE=/usr/lib/openssh/sshd-session",
                     "_EXE=/usr/bin/login", "_EXE=/usr/bin/su", "_EXE=/usr/bin/sudo", "+", "_UID=0", "SYSLOG_IDENTIFIER=webmin"):
            self.assertIn(word, a)
        self.assertIn("--after-cursor=s=abc;i=1", mod.journal_args("s=abc;i=1"))
        self.assertNotIn("--lines=0", mod.journal_args("s=abc;i=1"))

    def test_watch_writes_events_and_keeps_its_place(self):
        recs = []
        with open(FIXTURES, encoding="utf-8") as fh:
            for raw in fh:
                if raw.strip() and not raw.startswith("#"):
                    fx = json.loads(raw)
                    fx["rec"]["__CURSOR"] = "s=lab;i=%d" % (len(recs) + 1)
                    recs.append(fx)
        with open(os.path.join(self.lab.root, "stub/journal.out"), "w", encoding="utf-8") as fh:
            fh.write("this is not json\n")
            for fx in recs:
                fh.write(json.dumps(fx["rec"]) + "\n")
        p = subprocess.Popen([sys.executable, "-I", PROGRAM, "--root", self.lab.root, "watch"], stderr=subprocess.DEVNULL)
        want = sum(1 for fx in recs if fx["want"] is not None)
        deadline = time.time() + 20
        cpath = os.path.join(self.lab.state_dir, "cursor")
        while time.time() < deadline:
            if len(os.listdir(self.lab.queue)) >= want and os.path.exists(cpath):
                break
            time.sleep(0.1)
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(timeout=10), 0)
        names = [n for n in os.listdir(self.lab.queue) if n.endswith(".ev")]
        self.assertEqual(len(names), want)
        self.assertTrue(all(n.startswith("j.") for n in names))
        with open(cpath) as fh:
            self.assertEqual(fh.read().strip(), "s=lab;i=%d" % len(recs))
        self.assertTrue(os.path.exists(os.path.join(self.lab.state_dir, "watch.alive")))
        with open(os.path.join(self.lab.root, "stub/journal.args")) as fh:
            self.assertIn("--lines=0", fh.read())
        # the next start goes on after its last place
        p = subprocess.Popen([sys.executable, "-I", PROGRAM, "--root", self.lab.root, "watch"], stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=10)
        with open(os.path.join(self.lab.root, "stub/journal.args")) as fh:
            self.assertIn("--after-cursor=s=lab;i=%d" % len(recs), fh.read().splitlines()[-1])

    def test_watch_forgets_a_place_the_journal_no_longer_has(self):
        cpath = os.path.join(self.lab.state_dir, "cursor")
        with open(cpath, "w") as fh:
            fh.write("s=gone;i=5\n")
        open(os.path.join(self.lab.root, "stub/journal.exit"), "w").close()
        p = subprocess.run([sys.executable, "-I", PROGRAM, "--root", self.lab.root, "watch"], stderr=subprocess.DEVNULL, timeout=20)
        self.assertEqual(p.returncode, 1)       # systemd starts it again (Restart=always)
        self.assertFalse(os.path.exists(cpath))


class TestSender(Base):
    def one(self, s, wait=0.0):
        self.lab.step(s, wait)
        return list(self.lab.sent)

    def test_ssh_root_password_alerts_at_once(self):
        s = self.lab.sender()
        self.lab.hook("sshd", "root", "4101", tty="ssh", rhost="203.0.113.5")
        self.lab.journal("accepted", "4101", svc="sshd", user="root", method="password", rhost="203.0.113.5", port="40022")
        sent = self.one(s)
        self.assertEqual(len(sent), 1)
        self.assertIn("auto_sec login alert: lab-host", sent[0])
        self.assertIn("root logged in over SSH with a PASSWORD", sent[0])
        self.assertIn("from: 203.0.113.5", sent[0])
        self.assertIn("seen by: login hook and journal", sent[0])
        self.assertIn("UTC", sent[0])
        self.assertNotIn(TOKEN, sent[0])
        self.assertEqual(os.listdir(self.lab.queue), [])
        self.assertEqual(s.state["day"]["alerts"], 1)

    def test_ssh_root_quiet_key_is_quiet_and_counted(self):
        s = self.lab.sender()
        self.lab.hook("sshd", "root", "4110", rhost="198.51.100.7")
        self.lab.journal("accepted", "4110", svc="sshd", user="root", method="publickey", rhost="198.51.100.7",
                         keytype="ED25519", fp=QUIET_FP)
        self.lab.drain(s, 5)
        self.assertEqual(self.lab.sent, [])
        self.assertEqual(s.state["day"]["quiet"], 1)
        self.assertEqual(s.state["day"]["alerts"], 0)

    def test_ssh_root_other_key_alerts_with_its_fingerprint(self):
        s = self.lab.sender()
        self.lab.hook("sshd", "root", "4111", rhost="198.51.100.7")
        self.lab.journal("accepted", "4111", svc="sshd", user="root", method="publickey", rhost="198.51.100.7",
                         keytype="RSA", fp=OTHER_FP)
        sent = self.one(s)
        self.assertEqual(len(sent), 1)
        self.assertIn("with a key (RSA %s)" % OTHER_FP, sent[0])

    def test_root_is_never_a_quiet_account(self):
        self.lab.write_conf("root auditor", QUIET_FP, "true", "")
        s = self.lab.sender()
        self.lab.hook("sshd", "root", "4101", rhost="203.0.113.5")
        self.lab.journal("accepted", "4101", svc="sshd", user="root", method="password", rhost="203.0.113.5")
        self.lab.hook("su", "root", "5200", ruser="auditor", tty="pts/0", ruid="1001")
        self.lab.journal("pam_open", "5200", svc="su", user="root", ruser="auditor", byuid="1001")
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertIn("2 logins", self.lab.sent[0])

    def test_quiet_account_over_ssh_also_with_a_password(self):
        s = self.lab.sender()
        self.lab.hook("sshd", "auditor", "4130", rhost="198.51.100.9")
        self.lab.journal("accepted", "4130", svc="sshd", user="auditor", method="password", rhost="198.51.100.9")
        self.lab.drain(s, 5)
        self.assertEqual(self.lab.sent, [])
        self.assertEqual(s.state["day"]["quiet"], 1)

    def test_quiet_key_is_quiet_for_any_account(self):
        s = self.lab.sender()
        self.lab.hook("sshd", "deploy", "4131", rhost="198.51.100.7")
        self.lab.journal("accepted", "4131", svc="sshd", user="deploy", method="publickey", rhost="198.51.100.7",
                         keytype="ED25519", fp=QUIET_FP)
        self.lab.drain(s, 5)
        self.assertEqual(self.lab.sent, [])

    def test_ssh_without_sshds_line_waits_two_seconds_then_alerts(self):
        s = self.lab.sender()
        self.lab.hook("sshd", "root", "4140", rhost="203.0.113.5")
        self.assertEqual(self.one(s), [])
        self.assertEqual(self.one(s, 1.9), [])
        sent = self.one(s, 0.2)
        self.assertEqual(len(sent), 1)
        self.assertIn("key or password not known", sent[0])
        self.assertIn("the journal reader did not report this login", sent[0])
        # sshd's line comes late: said in a second message, not as a second login
        self.lab.journal("accepted", "4140", svc="sshd", user="root", method="password", rhost="203.0.113.5")
        self.lab.drain(s, 4)
        self.assertEqual(len(self.lab.sent), 2)
        self.assertIn("More on the SSH login of root", self.lab.sent[1])
        self.assertIn("with a PASSWORD", self.lab.sent[1])
        self.assertEqual(s.state["day"]["alerts"], 1)

    def test_late_line_with_a_quiet_key_sends_nothing_more(self):
        s = self.lab.sender()
        self.lab.hook("sshd", "root", "4141", rhost="198.51.100.7")
        self.lab.drain(s, 2.5)
        self.assertEqual(len(self.lab.sent), 1)
        self.lab.journal("accepted", "4141", svc="sshd", user="root", method="publickey", rhost="198.51.100.7", fp=QUIET_FP)
        self.lab.journal("pam_open", "4141", svc="sshd", user="root", byuid="0")
        self.lab.drain(s, 4)
        self.assertEqual(len(self.lab.sent), 1)

    def test_journal_only_login_names_the_missing_hook(self):
        s = self.lab.sender()
        self.lab.journal("accepted", "4150", svc="sshd", user="root", method="password", rhost="203.0.113.5")
        self.assertEqual(self.one(s), [])
        sent = self.one(s, 2.1)
        self.assertEqual(len(sent), 1)
        self.assertIn("seen by: journal (the login hook did not report this login)", sent[0])
        self.assertEqual(s.state["day"]["journal_only"], 1)

    def test_console_is_never_quiet(self):
        s = self.lab.sender()
        self.lab.hook("login", "auditor", "280", tty="/dev/ttyS0")
        self.lab.journal("pam_open", "280", svc="login", user="auditor", ruser="LOGIN", byuid="0")
        self.lab.hook("login", "root", "281", tty="/dev/tty1")
        self.lab.journal("login_line", "281", svc="login", user="root", tty="/dev/tty1")
        self.lab.drain(s, 2)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertIn("auditor logged in on the console (/dev/ttyS0)", self.lab.sent[0])
        self.assertIn("root logged in on the console (/dev/tty1)", self.lab.sent[0])

    def test_su(self):
        s = self.lab.sender()
        # deploy -> root: alert
        self.lab.hook("su", "root", "5200", ruser="deploy", tty="pts/0", ruid="1000")
        self.lab.journal("pam_open", "5200", svc="su", user="root", ruser="deploy", byuid="1000")
        self.lab.journal("su_line", "5200", svc="su", user="root", ruser="deploy", tty="pts/0")
        # root -> postgres (a backup script): not a login
        self.lab.hook("su-l", "postgres", "5201", ruser="root", ruid="0")
        self.lab.journal("pam_open", "5201", svc="su-l", user="postgres", ruser="root", byuid="0")
        # deploy -> auditor (a quiet account): quiet
        self.lab.hook("su", "auditor", "5202", ruser="deploy", tty="pts/1", ruid="1000")
        self.lab.journal("pam_open", "5202", svc="su", user="auditor", ruser="deploy", byuid="1000")
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertIn("deploy became root with su", self.lab.sent[0])
        self.assertNotIn("postgres", self.lab.sent[0])
        self.assertEqual((s.state["day"]["alerts"], s.state["day"]["by_root"], s.state["day"]["quiet"]), (1, 1, 1))

    def test_counts_of_a_login_that_sends_nothing_are_saved(self):
        # the sender's loop: scan, ripe, flush, save. The count of a login that
        # waited for the other sensor is written at its next pass, not at the
        # next alert (status reads the file).
        s = self.lab.sender()
        self.lab.hook("su", "root", "5300", ruser="root", ruid="0")
        self.lab.step(s)
        s.save()
        self.assertEqual(mod.load_state()["day"]["by_root"], 0)
        self.lab.step(s, 1.5)
        s.save()
        self.assertEqual(mod.load_state()["day"]["by_root"], 1)
        self.assertEqual(self.lab.sent, [])

    def test_sudo(self):
        s = self.lab.sender()
        # sudo -s: only sudo's own line, after the wait for a hook that does not come
        self.lab.journal("sudo_cmd", "5310", svc="sudo", ruser="deploy", user="root", tty="pts/0", cmd="/bin/bash")
        self.assertEqual(self.one(s), [])
        sent = self.one(s, 1.1)
        self.assertEqual(len(sent), 1)
        self.assertIn("deploy opened a shell as root with sudo (/bin/bash)", sent[0])
        # sudo -i: hook and line, one message
        self.lab.hook("sudo-i", "root", "5311", ruser="deploy", tty="/dev/pts/2", ruid="0")
        self.lab.journal("sudo_cmd", "5311", svc="sudo", ruser="deploy", user="root", tty="pts/2", cmd="/bin/bash")
        self.lab.journal("pam_open", "5311", svc="sudo-i", user="root", ruser="deploy", byuid="1000")
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 2)
        self.assertIn("with sudo -i", self.lab.sent[1])
        # root runs sudo -s: not a login
        self.lab.journal("sudo_cmd", "5312", svc="sudo", ruser="root", user="root", cmd="/bin/bash")
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 2)
        self.assertEqual(s.state["day"]["by_root"], 1)
        # a line that cannot be read safely is reported
        self.lab.journal("sudo_cmd", "5313", svc="sudo", ruser="deploy", user="root", odd="1")
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 3)
        self.assertIn("cannot be read safely", self.lab.sent[2])

    def test_unknown_door_root_always_alerts(self):
        self.lab.write_conf("root auditor", QUIET_FP, "true", "")
        s = self.lab.sender()
        self.lab.hook("cockpit", "root", "7000", rhost="198.51.100.7")
        self.lab.hook("vsftpd", "auditor", "7001", rhost="198.51.100.7")
        self.lab.drain(s, 2)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertIn("root logged in through PAM service 'cockpit', a door auto_sec does not know", self.lab.sent[0])
        self.assertNotIn("vsftpd", self.lab.sent[0])

    def test_webmin(self):
        s = self.lab.sender()
        self.lab.hook("webmin", "root", "6400", tty="10000", rhost="198.51.100.7")
        self.lab.journal("web_login", "6401", svc="webmin", user="root", rhost="198.51.100.7")
        self.lab.drain(s, 2)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertIn("root logged in to Webmin", self.lab.sent[0])
        self.assertIn("seen by: login hook and journal", self.lab.sent[0])
        # a second login of the same account from the same address is a second alert
        self.lab.hook("webmin", "root", "6402", tty="10000", rhost="198.51.100.7")
        self.lab.journal("web_login", "6403", svc="webmin", user="root", rhost="198.51.100.7")
        self.lab.drain(s, 2)
        self.assertEqual(len(self.lab.sent), 2)

    def test_burst_is_one_message(self):
        s = self.lab.sender()
        for i in range(5):
            pid = str(4200 + i)
            self.lab.hook("sshd", "root", pid, rhost="203.0.113.%d" % (10 + i))
            self.lab.journal("accepted", pid, svc="sshd", user="root", method="password", rhost="203.0.113.%d" % (10 + i))
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertIn("auto_sec login alerts: lab-host (5 logins)", self.lab.sent[0])
        for i in range(5):
            self.assertIn("from: 203.0.113.%d" % (10 + i), self.lab.sent[0])

    def test_many_logins_split_and_no_faster_than_one_message_a_second(self):
        s = self.lab.sender()
        times = []
        orig = self.lab.fake_send

        def send(text):
            times.append(self.lab.clock.t)
            return orig(text)
        s.send = send
        for i in range(60):
            pid = str(8000 + i)
            self.lab.hook("sshd", "root", pid, rhost="203.0.113.77")
            self.lab.journal("accepted", pid, svc="sshd", user="root", method="password", rhost="203.0.113.77")
        self.lab.drain(s, 30, tick=0.25)
        self.assertGreater(len(self.lab.sent), 1)
        self.assertTrue(all(len(t) <= 4000 for t in self.lab.sent))
        self.assertEqual(sum(t.count("with a PASSWORD") for t in self.lab.sent), 60)
        self.assertTrue(all(b - a >= mod.SEND_GAP - 0.01 for a, b in zip(times, times[1:])), times)

    def test_retries_until_it_goes_out(self):
        s = self.lab.sender()
        self.lab.answers = [{"error": "URLError", "retry": 0}] * 4
        self.lab.hook("sshd", "root", "4101", rhost="203.0.113.5")
        self.lab.journal("accepted", "4101", svc="sshd", user="root", method="password", rhost="203.0.113.5")
        self.lab.step(s)
        self.assertEqual(self.lab.sent, [])
        self.assertTrue(s.state["fail_since"])
        self.assertEqual(s.state["fail_why"], "URLError")
        self.lab.drain(s, 60)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertEqual(self.lab.answers, [])
        self.assertEqual(s.state["fail_since"], 0)

    def test_429_waits_as_long_as_telegram_says(self):
        s = self.lab.sender()
        self.lab.answers = [{"error": "HTTP 429", "retry": 7}]
        self.lab.hook("sshd", "root", "4101", rhost="203.0.113.5")
        self.lab.journal("accepted", "4101", svc="sshd", user="root", method="password", rhost="203.0.113.5")
        t0 = self.lab.clock.t
        self.lab.step(s)
        self.lab.drain(s, 6.5, tick=0.25)
        self.assertEqual(self.lab.sent, [])
        # logins during the wait join the same message
        self.lab.hook("login", "root", "281", tty="/dev/ttyS0")
        self.lab.journal("pam_open", "281", svc="login", user="root", byuid="0")
        self.lab.drain(s, 3, tick=0.25)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertGreaterEqual(self.lab.clock.t - t0, 7)
        self.assertIn("2 logins", self.lab.sent[0])

    def test_gives_up_after_ten_minutes_and_says_so_later(self):
        s = self.lab.sender()
        self.lab.answers = [{"error": "URLError", "retry": 0}] * 1000
        self.lab.hook("sshd", "root", "4101", rhost="203.0.113.5")
        self.lab.journal("accepted", "4101", svc="sshd", user="root", method="password", rhost="203.0.113.5")
        self.lab.drain(s, 700, tick=5)
        self.assertEqual(self.lab.sent, [])
        self.assertEqual(s.state["unsent"]["count"], 1)
        self.assertEqual(s.state["alerts"], [])
        self.lab.answers = []
        self.lab.hook("login", "root", "281", tty="/dev/ttyS0")
        self.lab.journal("pam_open", "281", svc="login", user="root", byuid="0")
        self.lab.drain(s, 70, tick=1)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertIn("root logged in on the console", self.lab.sent[0])
        self.assertIn("Not sent earlier", self.lab.sent[0])
        self.assertIn("1 alert(s)", self.lab.sent[0])
        self.assertIn("root ssh from 203.0.113.5", self.lab.sent[0])
        self.assertEqual(s.state["unsent"]["count"], 0)

    def test_what_waits_survives_a_restart(self):
        s = self.lab.sender()
        self.lab.answers = [{"error": "URLError", "retry": 0}] * 3
        self.lab.hook("sshd", "root", "4101", rhost="203.0.113.5")
        self.lab.journal("accepted", "4101", svc="sshd", user="root", method="password", rhost="203.0.113.5")
        self.lab.step(s)
        s.save()
        self.lab.answers = []
        s2 = self.lab.sender()
        self.lab.drain(s2, 3)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertIn("with a PASSWORD", self.lab.sent[0])

    def test_logins_that_keep_coming_while_nothing_goes_out_stay_bounded(self):
        s = self.lab.sender()
        self.lab.answers = [{"error": "URLError", "retry": 0}] * 1000      # Telegram cannot be reached
        extra = 60
        for i in range(mod.ALERTS_MAX + extra):
            self.lab.hook("sshd", "root", str(5000 + i), rhost="203.0.113.5")
            self.lab.journal("accepted", str(5000 + i), svc="sshd", user="root", method="password", rhost="203.0.113.5")
        self.lab.step(s)
        self.assertEqual(self.lab.sent, [])
        self.assertEqual(len(s.state["alerts"]), mod.ALERTS_MAX)       # what waits stays bounded ...
        self.assertEqual(s.state["unsent"]["count"], extra)             # ... and every login is still counted
        self.assertLessEqual(len(s.state["unsent"]["lines"]), 30)
        self.assertEqual(s.state["day"]["alerts"], mod.ALERTS_MAX + extra)
        s.save()
        self.assertLess(os.path.getsize(os.path.join(self.lab.state_dir, "state.json")), 200000)
        self.lab.answers = []                                           # Telegram is back
        self.lab.drain(s, 60)
        self.assertIn("Not sent one by one (more than %d logins waited at once" % mod.ALERTS_MAX, self.lab.sent[0])
        self.assertIn(": %d alert(s)" % extra, self.lab.sent[0])
        self.assertIn("... and %d more (not listed)." % (extra - 15), self.lab.sent[0])
        self.assertEqual((s.state["alerts"], s.state["unsent"]["count"]), ([], 0))
        self.assertEqual("\n".join(self.lab.sent).count("root logged in over SSH with a PASSWORD"), mod.ALERTS_MAX)

    def test_an_odd_state_file_does_not_stop_the_sender(self):
        # written by another version, or cut short by a full disk: valid JSON in another shape
        with open(os.path.join(self.lab.state_dir, "state.json"), "w", encoding="utf-8") as fh:
            json.dump({"day": "x", "alerts": [{"user": 7}, "junk", {"t": "soon", "door": "ssh", "user": "root", "ready": "x"}],
                       "notices": [{"kind": 3}, {"kind": "text"}, "junk"], "unsent": {"count": "many", "lines": "none"},
                       "said": [1], "last_alive": "yesterday", "fail_since": None, "fail_why": 5, "day_from": []}, fh)
        s = self.lab.sender()
        self.lab.hook("login", "root", "281", tty="/dev/tty1")
        self.lab.journal("pam_open", "281", svc="login", user="root", byuid="0")
        self.lab.drain(s, 5)
        self.assertIn("root logged in on the console", "\n".join(self.lab.sent))
        self.assertEqual(s.state["alerts"], [])

    def test_a_stop_loses_no_login_that_was_already_taken(self):
        s = self.lab.sender()
        self.lab.hook("sshd", "root", "4160", rhost="203.0.113.5")
        self.lab.step(s)            # taken out of the queue; it still waits for sshd's own line
        self.assertEqual(os.listdir(self.lab.queue), [])
        self.assertEqual(self.lab.sent, [])
        s.shutdown()                # the service is stopped at this moment ...
        s2 = self.lab.sender()      # ... and started again
        self.lab.drain(s2, 3)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertIn("root logged in over SSH", self.lab.sent[0])
        self.assertIn("from: 203.0.113.5", self.lab.sent[0])

    def test_alive_message(self):
        s = self.lab.sender()
        self.lab.hook("sshd", "root", "4110", rhost="198.51.100.7")
        self.lab.journal("accepted", "4110", svc="sshd", user="root", method="publickey", fp=QUIET_FP)
        self.lab.hook("login", "root", "281", tty="/dev/ttyS0")
        self.lab.journal("pam_open", "281", svc="login", user="root", byuid="0")
        self.lab.journal("hook_fail", "4120", svc="sshd", why="caught signal 9")
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertEqual(mod.main(["--root", self.lab.root, "alive"]), 0)
        mod.ROOT = self.lab.root
        before = self.lab.clock.t
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 2)
        text = self.lab.sent[1]
        self.assertEqual(text.split("\n")[0], "auto_sec alive: lab-host")
        self.assertIn("- logins that sent an alert: 1", text)
        self.assertIn("- quiet logins: 1", text)
        self.assertIn("- events from the login hook: 2; logins in the journal: 2", text)
        self.assertIn("the login hook failed or was cut off 1 time(s)", text)
        self.assertGreaterEqual(s.state["last_alive"], before)
        self.assertEqual(s.state["day"]["alerts"], 0)
        self.assertEqual(s.state["day_from"], s.state["last_alive"])

    def test_damaged_event_file_still_alerts(self):
        s = self.lab.sender()
        self.lab.hook("sshd", "root", "4101", complete=False)
        self.lab.hook("", "", "", raw=b"")
        self.assertEqual(self.one(s), [])
        self.assertEqual(len(os.listdir(self.lab.queue)), 2)      # perhaps still being written
        self.lab.drain(s, 8)
        self.assertEqual(os.listdir(self.lab.queue), [])
        self.assertTrue(any("its record is incomplete" in t for t in self.lab.sent))

    def test_odd_values_cannot_shape_the_message(self):
        s = self.lab.sender()
        evil = "evil\"host\nauto_sec alive: lab-host\n$(id) `id` \x1b[31m" + "A" * 3000
        self.lab.hook("sshd", "ro\"ot\nx", "4101", rhost=evil, tty="/dev/pts/9\n")
        self.lab.journal("accepted", "4101", svc="sshd", user="root", method="password", rhost="203.0.113.5")
        sent = self.one(s)
        self.assertEqual(len(sent), 1)
        lines = sent[0].split("\n")
        self.assertEqual(lines[0], "auto_sec login alert: lab-host")
        self.assertEqual(len([ln for ln in lines if ln.startswith("auto_sec alive")]), 0)
        self.assertTrue(all(32 <= ord(c) < 127 for ln in lines for c in ln))
        self.assertLess(len(sent[0]), 900)

    def test_sudo_arguments_are_not_sent(self):
        s = self.lab.sender()
        ev = mod.parse_sudo("  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/su - --pty SECRETVALUE")
        ev.update({"src": "journal", "app": "5310"})
        mod.write_event("j", ev)
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertNotIn("SECRETVALUE", self.lab.sent[0])

    def test_journal_only_mode_does_not_wait_for_a_hook(self):
        self.lab.write_conf("auditor", QUIET_FP, "false", "")
        s = self.lab.sender()
        self.lab.journal("accepted", "4150", svc="sshd", user="root", method="password", rhost="203.0.113.5")
        sent = self.one(s)
        self.assertEqual(len(sent), 1)
        self.assertIn("seen by: journal", sent[0])
        self.assertNotIn("did not report", sent[0])
        self.assertEqual(s.state["day"]["journal_only"], 0)

    def test_checker_gone_is_said_once_an_hour(self):
        s = self.lab.sender()
        for _ in range(3):
            s.notice("checker_down", {"why": "auto-sec-check.timer is inactive"})
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 1)
        self.assertIn("The checker that watches the watcher is not running: auto-sec-check.timer is inactive", self.lab.sent[0])
        self.lab.clock.t += 3601
        s.notice("checker_down", {"why": "auto-sec-check.timer is inactive"})
        self.lab.drain(s, 3)
        self.assertEqual(len(self.lab.sent), 2)

    def test_checker_problem(self):
        now = time.time()
        up = now - 3600        # the service has been up for an hour
        check = os.path.join(self.lab.state_dir, "check.json")
        mod.write_json(check, {"last_run": now - 60})
        self.assertEqual(mod.checker_problem(now, up), "")
        with open(os.path.join(self.lab.root, "stub/states"), "w") as fh:
            fh.write("auto-sec-check.timer inactive\n")
        self.assertEqual(mod.checker_problem(now, up), "auto-sec-check.timer is inactive")
        # an install starts the timer after the services: a service that just started does not ask yet
        self.assertEqual(mod.checker_problem(now, now - 30), "")
        open(os.path.join(self.lab.root, "stub/states"), "w").close()
        mod.write_json(check, {"last_run": now - 3600})
        self.assertIn("the checker has not run since 20", mod.checker_problem(now, up))
        # after a boot the last run may be hours old, and the next one is 2 minutes away
        self.assertEqual(mod.checker_problem(now, now - 120), "")
        os.remove(check)
        self.assertEqual(mod.checker_problem(now, up), "the checker has not run since this service started")


class Sink:
    """tests/detection/fake_telegram.py as a child process."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="detect-sink.")
        self.proc = subprocess.Popen([sys.executable, "-I", FAKE, "--dir", self.dir])
        deadline = time.time() + 10
        self.port = 0
        while time.time() < deadline and not self.port:
            try:
                with open(os.path.join(self.dir, "port")) as fh:
                    self.port = int(fh.read().strip() or 0)
            except (OSError, ValueError):
                time.sleep(0.05)
        assert self.port, "the fake Telegram did not start"
        self.api = "http://127.0.0.1:%d" % self.port

    def mode(self, text):
        with open(os.path.join(self.dir, "mode"), "w") as fh:
            fh.write(text + "\n")

    def messages(self):
        with open(os.path.join(self.dir, "messages"), encoding="utf-8") as fh:
            return [json.loads(x) for x in fh if x.strip()]

    def requests(self):
        with open(os.path.join(self.dir, "requests")) as fh:
            return [x.split()[1] for x in fh if x.strip()]

    def wait(self, n, seconds=15):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if len(self.messages()) >= n:
                return True
            time.sleep(0.1)
        return False

    def close(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        shutil.rmtree(self.dir, ignore_errors=True)


class WithSink(Base):
    def setUp(self):
        super().setUp()
        self.sink = Sink()
        self.addCleanup(self.sink.close)
        self.lab.write_conf("auditor", QUIET_FP, "true", self.sink.api)

    def run_cmd(self, *args, timeout=60):
        return subprocess.run([sys.executable, "-I", PROGRAM, "--root", self.lab.root] + list(args),
                              capture_output=True, text=True, timeout=timeout)

    def states(self, text):
        with open(os.path.join(self.lab.root, "stub/states"), "w") as fh:
            fh.write(text)

    def beats(self, age=0):
        for name in ("sender.alive", "watch.alive"):
            p = os.path.join(self.lab.state_dir, name)
            open(p, "a").close()
            os.utime(p, (time.time() - age, time.time() - age))


class TestTelegram(WithSink):
    def test_send_and_answers(self):
        conf = mod.load_conf()
        self.assertTrue(conf["test_mode"])
        ok, mid = mod.tg_send(conf, "hello from the lab")
        self.assertTrue(ok)
        self.assertEqual(mid, 1)
        self.assertEqual(self.sink.messages()[0]["text"], "hello from the lab")
        self.assertEqual(self.sink.messages()[0]["chat_id"], "-100123")
        self.sink.mode("429 17 1")
        self.assertEqual(mod.tg_send(conf, "x"), (False, {"error": "HTTP 429", "retry": 17}))
        self.sink.mode("500 1")
        self.assertEqual(mod.tg_send(conf, "x"), (False, {"error": "HTTP 500", "retry": 0}))
        self.assertTrue(mod.tg_send(conf, "again")[0])

    def test_every_call_has_a_time_limit(self):
        conf = mod.load_conf()
        self.sink.mode("hang 6 1")
        old = mod.HTTP_TIMEOUT
        mod.HTTP_TIMEOUT = 1
        try:
            t0 = time.time()
            ok, info = mod.tg_send(conf, "x")
        finally:
            mod.HTTP_TIMEOUT = old
        self.assertFalse(ok)
        self.assertLess(time.time() - t0, 4)
        self.assertNotIn(TOKEN, json.dumps(info))

    def test_wrong_token_and_no_token_in_any_output(self):
        self.lab.write_conf("auditor", QUIET_FP, "true", self.sink.api, token="87654321:another-token-that-is-wrong-0000")
        r = self.run_cmd("test")
        self.assertEqual(r.returncode, 1)
        out = json.loads(r.stdout)
        self.assertEqual((out["ok"], out["error"]), (False, "HTTP 401"))
        self.assertNotIn("87654321", r.stdout + r.stderr)

    def test_an_error_while_the_request_is_built_cannot_show_the_token(self):
        conf = mod.load_conf()
        real = mod.urllib.request.Request

        def boom(url, *_args, **_kwargs):
            raise ValueError("unknown url type: %r" % url)      # urllib's own message names the address
        mod.urllib.request.Request = boom
        try:
            ok, info = mod.tg_send(conf, "x")                   # must not raise: a traceback would show the token
        finally:
            mod.urllib.request.Request = real
        self.assertEqual((ok, info), (False, {"error": "ValueError", "retry": 0}))

    def test_only_a_loopback_address_is_taken(self):
        for api in ("http://198.51.100.9:8080", "https://example.org", "http://127.0.0.1.example.org:80", "http://localhost:80"):
            self.lab.write_conf("auditor", QUIET_FP, "true", api)
            conf = mod.load_conf()
            self.assertFalse(conf["test_mode"])
            self.assertIn("api_base is not a loopback address", conf["bad"])
            self.assertEqual(mod.tg_send(conf, "x")[0], False)
        self.assertEqual(self.sink.requests(), [])

    def test_test_message(self):
        r = self.run_cmd("test")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertTrue(out["ok"] and out["test_mode"])
        self.assertRegex(out["id"], r"^[0-9a-f]{8}$")
        self.assertIn("auto_sec test %s: alerts from lab-host reach this chat." % out["id"], self.sink.messages()[0]["text"])

    def test_missing_settings(self):
        self.lab.write_conf("auditor", QUIET_FP, "true", self.sink.api, token="CHANGE_ME")
        r = self.run_cmd("test")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(r.stdout)["error"], "not configured")
        os.unlink(os.path.join(self.lab.root, "etc/auto-sec/detect.conf"))
        r = self.run_cmd("status", "--json")
        self.assertEqual(json.loads(r.stdout)["verdict"], "absent")
        self.assertEqual(self.run_cmd("check").returncode, 2)


class TestEndToEnd(WithSink):
    def test_the_real_sender_and_the_real_hook(self):
        hook = os.path.join(self.lab.root, "hook")
        with open(os.path.join(REPO, "roles/08-detection/files/auto-sec-login-hook")) as fh:
            body = fh.read().replace("Q=/var/spool/auto-sec/events", "Q=" + self.lab.queue)
        with open(hook, "w") as fh:
            fh.write(body)
        os.chmod(hook, 0o755)
        p = subprocess.Popen([sys.executable, "-I", PROGRAM, "--root", self.lab.root, "send"], stderr=subprocess.DEVNULL)
        try:
            t0 = time.time()
            env = {"PAM_TYPE": "open_session", "PAM_SERVICE": "login", "PAM_USER": "root", "PAM_TTY": "/dev/ttyS0"}
            self.assertEqual(subprocess.run([hook], env=env, timeout=10).returncode, 0)
            self.assertTrue(self.sink.wait(1, 10))
            took = time.time() - t0
            msg = self.sink.messages()[0]["text"]
            self.assertIn("root logged in on the console (/dev/ttyS0)", msg)
            self.assertLess(took, 3.0, "hook to message took %.1f s" % took)
            # a burst while Telegram says "too many requests"
            self.sink.mode("429 2 2")
            for i in range(4):
                env = {"PAM_TYPE": "open_session", "PAM_SERVICE": "login", "PAM_USER": "root", "PAM_TTY": "/dev/tty%d" % i}
                subprocess.run([hook], env=env, timeout=10)
            self.assertTrue(self.sink.wait(2, 20))
            time.sleep(2.5)
            msgs = self.sink.messages()
            self.assertEqual(len(msgs), 2, [m["text"][:60] for m in msgs])
            self.assertIn("(4 logins)", msgs[1]["text"])
            self.assertEqual(self.sink.requests().count("429"), 2)
            self.assertTrue(os.path.exists(os.path.join(self.lab.state_dir, "sender.alive")))
        finally:
            p.send_signal(signal.SIGTERM)
            self.assertEqual(p.wait(timeout=10), 0)
        st = load(os.path.join(self.lab.state_dir, "state.json"))
        self.assertEqual(st["day"]["alerts"], 5)
        self.assertTrue(st["installed"])


class TestChecker(WithSink):
    def test_all_well_sends_nothing(self):
        self.beats()
        r = self.run_cmd("check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.sink.messages(), [])
        self.assertTrue(load(os.path.join(self.lab.state_dir, "check.json"))["last_run"])

    def test_problem_once_then_hourly_then_working_again(self):
        self.beats()
        self.states("auto-sec-alert.service inactive\n")
        self.run_cmd("check")
        msgs = self.sink.messages()
        self.assertEqual(len(msgs), 1)
        self.assertIn("auto_sec detection problem: lab-host", msgs[0]["text"])
        self.assertIn("the sender is not running (auto-sec-alert.service: inactive)", msgs[0]["text"])
        self.assertIn("repeats every hour", msgs[0]["text"])
        self.run_cmd("check")
        self.assertEqual(len(self.sink.messages()), 1)        # five minutes later: not again
        path = os.path.join(self.lab.state_dir, "check.json")
        rec = load(path)
        rec["said"] -= 3601
        mod.write_json(path, rec)
        self.run_cmd("check")
        self.assertEqual(len(self.sink.messages()), 2)        # an hour later: again
        self.states("auto-sec-alert.service inactive\nauto-sec-login-watch.service failed\n")
        self.run_cmd("check")
        self.assertEqual(len(self.sink.messages()), 3)        # something more broke: at once
        self.assertIn("the journal reader is not running", self.sink.messages()[2]["text"])
        self.states("")
        self.run_cmd("check")
        self.assertEqual(len(self.sink.messages()), 4)
        self.assertIn("auto_sec detection is working again on lab-host", self.sink.messages()[3]["text"])
        self.run_cmd("check")
        self.assertEqual(len(self.sink.messages()), 4)

    def test_each_thing_it_asks(self):
        def problems():
            self.run_cmd("check")
            return " | ".join(load(os.path.join(self.lab.state_dir, "check.json"))["problems"])
        self.beats()
        self.assertEqual(problems(), "")
        self.beats(age=300)
        p = problems()
        self.assertIn("the sender has not answered since", p)
        self.assertIn("the journal reader has not answered since", p)
        self.beats()
        os.unlink(os.path.join(self.lab.root, "etc/pam.d/common-session"))
        self.assertIn("the login hook's line is no longer in /etc/pam.d/common-session", problems())
        self.lab.pam_ok()
        with open(os.path.join(self.lab.root, "usr/share/pam-configs/auto-sec-login-alert"), "w") as fh:
            fh.write("Name: somebody else\n")
        self.assertIn("the PAM profile /usr/share/pam-configs/auto-sec-login-alert is missing or was changed", problems())
        self.lab.pam_ok()
        os.unlink(os.path.join(self.lab.root, "usr/local/sbin/auto-sec-login-hook"))
        self.assertIn("the login hook /usr/local/sbin/auto-sec-login-hook is missing", problems())
        self.lab.pam_ok()
        ev = self.lab.hook("sshd", "root", "1")
        os.utime(ev, (time.time() - 600, time.time() - 600))
        self.assertIn("the queue is not moving: 1 event(s) wait", problems())
        os.unlink(ev)
        for unit, words in (("auto-sec-alert.path", "the sender's wake-up is not running"),
                            ("auto-sec-alive.timer", "the daily message's timer is not running")):
            self.states(unit + " inactive\n")
            self.assertIn(words, problems())
        self.states("")
        mod.write_json(os.path.join(self.lab.state_dir, "state.json"), {"fail_since": time.time() - 1200, "fail_why": "URLError"})
        self.assertIn("messages cannot be sent since", problems())
        mod.write_json(os.path.join(self.lab.state_dir, "state.json"), {"installed": time.time() - 3 * 86400, "last_alive": time.time() - 2 * 86400})
        due = mod.alive_due(mod.load_conf(), time.time())
        if time.time() - due > 1800:
            self.assertIn("the daily message of", problems())
        mod.write_json(os.path.join(self.lab.state_dir, "state.json"), {"installed": time.time() - 3 * 86400, "last_alive": time.time()})
        self.assertEqual(problems(), "")

    def test_journal_only_mode_does_not_ask_about_pam(self):
        self.lab.write_conf("auditor", QUIET_FP, "false", self.sink.api)
        self.beats()
        os.unlink(os.path.join(self.lab.root, "etc/pam.d/common-session"))
        os.unlink(os.path.join(self.lab.root, "usr/local/sbin/auto-sec-login-hook"))
        self.run_cmd("check")
        self.assertEqual(self.sink.messages(), [])

    def test_a_boot_is_said_once(self):
        self.beats()
        self.run_cmd("check")
        with open(os.path.join(self.lab.root, "proc/sys/kernel/random/boot_id"), "w") as fh:
            fh.write("99999999-2222-3333-4444-555555555555\n")
        self.run_cmd("check")
        self.run_cmd("check")
        msgs = self.sink.messages()
        self.assertEqual(len(msgs), 1)
        self.assertIn("lab-host started again (a boot)", msgs[0]["text"])

    def test_no_telegram_no_message_and_it_tries_again(self):
        self.beats()
        self.states("auto-sec-alert.service inactive\n")
        self.sink.mode("500 50")
        r = self.run_cmd("check")
        # not a failure of the checker's unit (that would send "the watcher was stopped"): it says so and tries again
        self.assertEqual(r.returncode, 0)
        self.assertIn("could not send the problem message (HTTP 500)", r.stderr)
        self.assertIn("problem: the sender is not running", r.stderr)
        self.assertEqual(self.sink.messages(), [])
        self.sink.mode("ok")
        self.run_cmd("check")
        self.assertEqual(len(self.sink.messages()), 1)

    def test_stopped_message(self):
        r = self.run_cmd("stopped", "auto-sec-login-watch.service", "exit-code")
        self.assertEqual(r.returncode, 0, r.stderr)
        msgs = self.sink.messages()
        self.assertEqual(len(msgs), 1)
        self.assertIn("auto_sec: the watcher on lab-host was stopped.", msgs[0]["text"])
        self.assertIn("Unit: auto-sec-login-watch.service (exit-code)", msgs[0]["text"])
        self.assertIn("After a crash it starts again by itself", msgs[0]["text"])        # a service restarts
        self.run_cmd("stopped", "auto-sec-login-watch.service", "exit-code")
        self.assertEqual(len(self.sink.messages()), 1)        # a unit that keeps failing: not a flood
        self.run_cmd("stopped", "auto-sec-alert.path")
        self.assertEqual(len(self.sink.messages()), 2)
        self.assertNotIn("starts again by itself", self.sink.messages()[1]["text"])       # a path unit does not
        self.assertIn("The checker says more within 5 minutes.", self.sink.messages()[1]["text"])

    def test_odd_state_files_stop_neither_the_checker_nor_the_status_nor_the_stop_message(self):
        for name, body in (("state.json", '{"unsent": 5, "alerts": {"a": 1}, "day": [], "last_alive": "x", "notices": 7}'),
                           ("check.json", '{"since": "x", "said": "y", "boot": 5, "codes": "z", "problems": 3}'),
                           ("stopped.json", '{"auto-sec-alert.service": "x", "other": []}')):
            with open(os.path.join(self.lab.state_dir, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        r = self.run_cmd("check")
        self.assertEqual((r.returncode, "Traceback" in r.stderr), (0, False), r.stderr)
        r = self.run_cmd("status")
        self.assertEqual((r.returncode in (0, 3), "Traceback" in r.stderr), (True, False), r.stderr)
        r = self.run_cmd("status", "--json")
        self.assertIn(json.loads(r.stdout)["verdict"], ("on", "dead"))
        before = len(self.sink.messages())
        r = self.run_cmd("stopped", "auto-sec-alert.service")
        self.assertEqual((r.returncode, "Traceback" in r.stderr), (0, False), r.stderr)
        self.assertEqual(len(self.sink.messages()), before + 1)         # and the stop message still goes out

    def test_stopped_by_an_auto_sec_run_or_a_shutdown_is_silent(self):
        marker = os.path.join(self.lab.root, "run/auto-sec/detect-planned")
        open(marker, "w").close()
        self.run_cmd("stopped", "auto-sec-alert.service")
        self.assertEqual(self.sink.messages(), [])
        os.utime(marker, (time.time() - 1000, time.time() - 1000))      # an old marker does not count
        self.run_cmd("stopped", "auto-sec-alert.service")
        self.assertEqual(len(self.sink.messages()), 1)
        os.unlink(marker)
        with open(os.path.join(self.lab.root, "stub/system"), "w") as fh:
            fh.write("stopping\n")
        self.run_cmd("stopped", "auto-sec-check.timer")
        self.assertEqual(len(self.sink.messages()), 1)

    def test_status(self):
        self.beats()
        mod.write_json(os.path.join(self.lab.state_dir, "state.json"), {"last_alive": 1795000000, "installed": time.time()})
        r = self.run_cmd("status", "--json")
        out = json.loads(r.stdout)
        self.assertEqual(out["verdict"], "on")
        self.assertEqual(out["line"], "detection: on, last alive message " + utc(1795000000))
        self.assertTrue(out["test_mode"])
        r = self.run_cmd("status")
        self.assertEqual(r.returncode, 0)
        self.assertIn("TEST MODE: messages go to http://127.0.0.1:", r.stdout)
        self.states("auto-sec-alert.service inactive\n")
        beat = os.path.join(self.lab.state_dir, "sender.alive")
        os.utime(beat, (1795003600, 1795003600))
        r = self.run_cmd("status", "--json")
        out = json.loads(r.stdout)
        self.assertEqual(out["verdict"], "dead")
        self.assertEqual(out["since"], 1795003600)
        self.assertTrue(out["line"].startswith("detection: DEAD since %s (the sender is not running" % utc(1795003600)), out["line"])
        self.assertEqual(self.run_cmd("status").returncode, 3)
        # a problem that does not stop alerts: still on, and said
        self.states("auto-sec-alive.timer inactive\n")
        self.beats()
        out = json.loads(self.run_cmd("status", "--json").stdout)
        self.assertEqual(out["verdict"], "on")
        self.assertIn("1 problem(s)", out["line"])


class Lines(unittest.TextTestResult):
    """One PASS or FAIL line per test, like the other suites."""

    @staticmethod
    def _name(test):
        cls, meth = test.id().split(".")[-2:]
        return "%-9s %s" % (cls[4:].lower(), test.shortDescription() or meth[5:].replace("_", " "))

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
