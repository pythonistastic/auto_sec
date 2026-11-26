#!/usr/bin/env python3
"""test_role.py - role 08's task files against lab trees, with one ansible-playbook.

LAB ONLY (tests/detection/semantics/run.sh). No root, nothing installed,
never the real Telegram. lab.yml runs role 08 as site.yml wires it (the
variable checks, the read-only preflight, the run plan, the layer 08
include) with every path of the role pointed into a lab tree:

  PAM         a tree built by a pinned release's own pam-auth-update
              (test_pam.Tree); the role's trial helper and the real
              pam-auth-update run on it
  systemd     stubs/systemctl. `start auto-sec-alert.service` starts the
              REAL sender (auto-sec-detect --root <lab> send) in the
              background; no journal reader runs
  Telegram    tests/detection/fake_telegram.py on 127.0.0.1, through the
              role's CI-only switch (autosec_ci_detect_api)
  the undo    a private copy of the REAL guard script (role 02), its paths
              block pointing into the lab, with stubs that start no timer;
              stubs/roles/02-ssh-hardening stands in for role 02's task
              file, which needs root
  the login   stubs/su: on a real server root's `su`, which PAM answers
  test        with the login hook; here it writes that event file

Usage: test_role.py --ansible PLAYBOOK --x DIR --work DIR
  --x     the unpacked pinned packages (<x>/<set>/<package>/{root,control})
Prints one PASS or FAIL line per check; exit 1 when one fails.
"""
import argparse
import configparser
import grp
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
STUBS = os.path.join(HERE, "stubs")
FAKE = os.path.join(REPO, "tests", "detection", "fake_telegram.py")
GUARD = os.path.join(REPO, "roles", "02-ssh-hardening", "files", "auto-sec-ssh-guard")
FIXTURES = os.path.join(HERE, "fixtures", "journal-lines.txt")
TOKEN = "12345678:TEST-TOKEN-ONLY-for-the-fake-sink"
QUIET_FP = "SHA256:91kTeUIf2aJCD8UWjmPB35/8mOW3iviwpjZ8Yz+JXR8"
NOTHING = "Nothing has been changed."
sys.dont_write_bytecode = True


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


pam = load("auto_sec_test_pam", os.path.join(HERE, "test_pam.py"))
detect = load("auto_sec_detect_for_role", os.path.join(REPO, "roles", "08-detection", "files", "auto-sec-detect"))
check, eq, info = pam.check, pam.eq, pam.info
LINE, SHOWN, NAME = pam.LINE, pam.SHOWN, pam.NAME
WHO = "role"


def norm(text):
    """Ansible's output with its quoting and line breaks taken out."""
    return re.sub(r"\s+", " ", text.replace('\\"', '"').replace("\\n", " "))


def read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def snap(root, skip=()):
    """Everything under root: path -> (kind, mode, link target or sha256)."""
    out = {}
    for d, dirs, names in os.walk(root):
        for n in dirs + names:
            p = os.path.join(d, n)
            rel = os.path.relpath(p, root)
            if any(rel == s or rel.startswith(s + "/") for s in skip):
                continue
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", 0, os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", stat.S_IMODE(st.st_mode), "")
            else:
                out[rel] = ("file", stat.S_IMODE(st.st_mode), sha(p))
    return out


def diff(a, b):
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


class Sink:
    """The fake Telegram on 127.0.0.1."""

    def __init__(self, work):
        self.dir = os.path.join(work, "sink")
        os.makedirs(self.dir)
        self.proc = subprocess.Popen([sys.executable, "-I", FAKE, "--dir", self.dir, "--port", "0"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.monotonic() + 15
        port = ""
        while time.monotonic() < end and not port:
            try:
                port = read(os.path.join(self.dir, "port")).strip()
            except OSError:
                time.sleep(0.1)
        if not port.isdigit():
            raise SystemExit("the fake Telegram did not start")
        self.api = "http://127.0.0.1:" + port
        self.seen = 0

    def all(self):
        try:
            return [json.loads(ln) for ln in read(os.path.join(self.dir, "messages")).split("\n") if ln.strip()]
        except OSError:
            return []

    def new(self, wait=0.0, want=1):
        """The texts that came in since the last call (waits up to `wait` s for `want` of them)."""
        end = time.monotonic() + wait
        msgs = self.all()
        while len(msgs) - self.seen < want and time.monotonic() < end:
            time.sleep(0.2)
            msgs = self.all()
        out = [m["text"] for m in msgs[self.seen:]]
        self.seen = len(msgs)
        return out

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class Result:
    def __init__(self, rc, log, out, after):
        self.rc, self.log, self.out, self.after = rc, log, out, after
        self.n = norm(log)

    def has(self, text):
        return norm(text) in self.n

    def plan_id(self):
        m = re.search(r"Plan id: ([0-9a-f]{12})", self.log)
        return m.group(1) if m else ""


class Ctx:
    def __init__(self, a):
        self.ansible = a.ansible
        self.x = a.x
        self.work = a.work
        self.sink = Sink(a.work)
        self.labs = []
        self.logs = []
        self.templates = {}
        self.user = pwd.getpwuid(os.getuid()).pw_name
        self.group = grp.getgrgid(os.getgid()).gr_name

    def template(self, name):
        """A pristine lab root for one release, built once and copied for every lab."""
        if name in self.templates:
            return self.templates[name]
        t = pam.Tree(self.x, self.work, name, "template")
        shutil.copy(os.path.join(t.pkg, "root", "usr", "share", "pam-configs", "unix"), t.path("usr/share/pam-configs/unix"))
        pam.write(t.path("usr/share/pam-configs/systemd"), pam.SYSTEMD_PROFILE)
        pam.write(t.path("usr/share/pam-configs/capability"), pam.CAP_PROFILE)
        p = t.pau("--package", "--force")
        if p.returncode != 0 or not os.path.exists(t.path("etc/pam.d/common-session")):
            raise SystemExit("%s: cannot build the lab's PAM tree: %s" % (name, p.stderr[-300:]))
        # what every Debian and Ubuntu server has anyway
        for d in ("usr/local/sbin", "etc/systemd/system/multi-user.target.wants", "etc/systemd/system/timers.target.wants", "stub",
                  "usr/bin", "usr/lib/x86_64-linux-gnu/security", "var/spool"):
            os.makedirs(t.path(d))
        os.makedirs(t.path("run/auto-sec"), mode=0o700)
        for s in ("systemctl", "su"):
            shutil.copy(os.path.join(STUBS, s), t.path("stub/" + s))
            os.chmod(t.path("stub/" + s), 0o755)
        os.symlink("/usr/bin/timeout", t.path("usr/bin/timeout"))
        pam.write(t.path("usr/lib/x86_64-linux-gnu/security/pam_exec.so"), "")
        self.templates[name] = t
        return t

    def close(self):
        for lab in self.labs:
            lab.stop()
        self.sink.close()


class Lab:
    """One lab root, its systemd stub state and its copy of the undo guard."""

    def __init__(self, ctx, name, release="noble", src=None):
        self.ctx = ctx
        self.tree = pam.Tree(ctx.x, ctx.work, release, name, src.tree if src else ctx.template(release))
        self.root = self.tree.root
        self.base = self.tree.base
        self.sd = os.path.join(self.base, "sd")
        os.makedirs(self.sd)
        self.n = 0
        ctx.labs.append(self)
        # the real guard, its paths block pointing into this lab
        gbin = os.path.join(self.base, "guard-bin")
        os.makedirs(gbin)
        for s in ("sshd", "systemctl", "systemd-run", "fail2ban-client", "logger", "ufw"):
            pam.write(os.path.join(gbin, s), "#!/bin/sh\necho \"%s $*\" >> '%s/guard.calls'\nexit 0\n" % (s, self.base), 0o755)
        out, skip, marks = [], False, 0
        for ln in read(GUARD).split("\n"):
            if ln == "# --- paths (tests rewrite this block) ---":
                marks += 1
                skip = True
                out += [ln, "readonly STATE_DIR=%s/var/lib/auto-sec/ssh-guard" % self.root] + [
                    "readonly %s=%s/%s" % (var, gbin, s) for var, s in (
                        ("SSHD", "sshd"), ("SYSTEMCTL", "systemctl"), ("SYSTEMD_RUN", "systemd-run"),
                        ("F2B", "fail2ban-client"), ("LOGGER", "logger"), ("UFW", "ufw"))]
                continue
            if ln == "# --- end paths ---":
                marks += 1
                skip = False
            if not skip:
                out.append(ln)
        if marks != 2:
            raise SystemExit("the guard script has no paths block to rewrite")
        self.guard = self.path("usr/local/sbin/auto-sec-ssh-guard")
        pam.write(self.guard, "\n".join(out), 0o700)

    def path(self, rel):
        return os.path.join(self.root, rel)

    def vars(self):
        L = self.root
        return {
            "autosec_server": "existing",
            "lab_local_mode": True,
            "_det_bin": L + "/usr/local/sbin/auto-sec-detect",
            "_det_hook": L + "/usr/local/sbin/auto-sec-login-hook",
            "_det_conf_dir": L + "/etc/auto-sec",
            "_det_conf": L + "/etc/auto-sec/detect.conf",
            "_det_spool": L + "/var/spool/auto-sec",
            "_det_queue": L + "/var/spool/auto-sec/events",
            "_det_state": L + "/var/lib/auto-sec/detect",
            "_det_unit_dir": L + "/etc/systemd/system",
            "_det_profile": L + "/usr/share/pam-configs/" + NAME,
            "_det_pam_before": L + "/var/lib/auto-sec/detect/pam-before.json",
            "_det_planned": L + "/run/auto-sec/detect-planned",
            "_det_guard_bin": self.guard,
            "_ssh_guard_bin": self.guard,
            "_det_guard_pending": L + "/var/lib/auto-sec/ssh-guard/pending",
            "_det_run_dir": L + "/run/auto-sec",
            "_det_sim_dir": L + "/run/auto-sec/det-sim",
            "_det_file_owner": self.ctx.user,
            "_det_file_group": self.ctx.group,
            "_det_pam_tool": self.tree.tool,
            "_det_pam_lab_args": ["--sysroot", L],
            "_det_pam_real_args": ["--root", L],
            "_det_pam_real_env": {"DEBCONF_SYSTEMRC": self.tree.dbconf, "DEBCONF_NOWARNINGS": "yes",
                                  "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent"},
            "_det_pam_root": L,
            "_det_su_argv": [L + "/stub/su"],
            "_det_systemctl": L + "/stub/systemctl",
            "_det_webmin_conf": L + "/etc/webmin/miniserv.conf",
            "_det_elsewhere_dirs": [L + "/lib/systemd/system", L + "/usr/lib/systemd/system", L + "/run/systemd/system"],
            "_det_cmd": ["/usr/bin/python3", "-I", L + "/usr/local/sbin/auto-sec-detect", "--root", L],
        }

    def env(self, ci=True, extra=None):
        e = dict(os.environ)
        e.update({
            "PATH": self.path("stub") + ":" + os.environ.get("PATH", "/usr/bin:/bin"),
            "LAB_ROOT": self.root, "LAB_SD": self.sd, "LAB_BEATS": self.path("var/lib/auto-sec/detect"),
            "LAB_SENDER": "/usr/bin/python3 -I %s --root %s send" % (self.path("usr/local/sbin/auto-sec-detect"), self.root),
            "ANSIBLE_ROLES_PATH": os.path.join(STUBS, "roles") + ":" + os.path.join(REPO, "roles"),
            "ANSIBLE_NOCOLOR": "1", "ANSIBLE_LOCALHOST_WARNING": "False", "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_RETRY_FILES_ENABLED": "False", "ANSIBLE_FORCE_COLOR": "0", "LC_ALL": "C.UTF-8",
        })
        for k in ("GITHUB_ACTIONS", "AUTOSEC_CI_DETECT", "AUTOSEC_CI_INJECT_FAILURE", "LAB_SU_RC", "LAB_ON_SHOW"):
            e.pop(k, None)
        if ci:
            e["GITHUB_ACTIONS"] = "true"
            e["AUTOSEC_CI_DETECT"] = "fake-telegram"
        e.update(extra or {})
        return e

    def play(self, extra=None, args=(), ci=True, env=None):
        """One ansible-playbook run of lab.yml against this lab."""
        self.n += 1
        v = self.vars()
        v.update(extra or {})
        out = os.path.join(self.base, "run%d.json" % self.n)
        v["lab_out"] = out
        vpath = os.path.join(self.base, "run%d.vars.json" % self.n)
        with open(vpath, "w", encoding="utf-8") as fh:
            json.dump(v, fh)
        p = subprocess.run([self.ctx.ansible, "-i", "localhost,", os.path.join(HERE, "lab.yml"), "-e", "@" + vpath] + list(args),
                           cwd=HERE, env=self.env(ci, env), capture_output=True, text=True, timeout=900, check=False)
        log = p.stdout + "\n" + p.stderr
        with open(os.path.join(self.base, "run%d.log" % self.n), "w", encoding="utf-8") as fh:
            fh.write(log)
        self.ctx.logs.append(log)

        def js(path):
            try:
                return json.loads(read(path))
            except (OSError, ValueError):
                return None
        return Result(p.returncode, log, js(out), js(out + ".after"))

    def calls(self):
        """The systemctl calls since the last look, without the read-only ones."""
        path = os.path.join(self.sd, "calls")
        try:
            lines = read(path).split("\n")
        except OSError:
            lines = []
        open(path, "w").close()
        return [ln for ln in lines if ln and ln.split()[0] not in ("show", "is-active", "list-units", "is-system-running")]

    def guard_calls(self):
        path = os.path.join(self.base, "guard.calls")
        try:
            lines = [ln for ln in read(path).split("\n") if ln]
        except OSError:
            lines = []
        open(path, "w").close()
        return lines

    def detect(self, *args):
        return subprocess.run(["/usr/bin/python3", "-I", self.path("usr/local/sbin/auto-sec-detect"), "--root", self.root] + list(args),
                              env=self.env(), capture_output=True, text=True, timeout=120, check=False)

    def status(self):
        try:
            return json.loads(self.detect("status", "--json").stdout)
        except ValueError:
            return {}

    def pam_files(self):
        return {rel: pam.sha(self.path(rel)) for rel in pam.TREE_FILES + ["usr/share/pam-configs/" + NAME]}

    def session(self):
        return read(self.path("etc/pam.d/common-session")).split("\n")

    def sender_pid(self):
        try:
            return int(read(os.path.join(self.sd, "sender.pid")).strip())
        except (OSError, ValueError):
            return 0

    def stop(self):
        pid = self.sender_pid()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass

    def event(self, rec):
        """A journal record, written to the lab's queue the way the journal reader writes it."""
        detect.ROOT = self.root
        try:
            return detect.write_event("j", detect.journal_record(rec))
        finally:
            detect.ROOT = ""


def run_out(lab):
    """Let the mark of the last auto_sec run be past (20 s after the run, on a real server).

    While it counts, stop messages and the checker are quiet.
    """
    mark = lab.path("run/auto-sec/detect-planned")
    if os.path.exists(mark):
        old = time.time() - 1000
        os.utime(mark, (old, old))


def fixture(**want):
    for ln in read(FIXTURES).split("\n"):
        if ln.startswith("{"):
            f = json.loads(ln)
            if all(f["want"].get(k) == v for k, v in want.items()):
                return f["rec"]
    raise SystemExit("no fixture line with %r" % want)


GROUPS = []


def group(fn):
    GROUPS.append(fn)
    return fn


def on(ctx, **more):
    v = {"detection_enabled": True, "telegram_bot_token": TOKEN, "telegram_chat_id": "-100123",
         "autosec_ci": True, "autosec_ci_detect_api": ctx.sink.api,
         "detection_quiet_accounts": ["auditor"],
         "detection_quiet_ssh_keys": [{"fingerprint": QUIET_FP, "label": "auto_sec runs"}]}
    v.update(more)
    return v


UNITS = ["auto-sec-alert.service", "auto-sec-login-watch.service", "auto-sec-alert.path", "auto-sec-alive.timer",
         "auto-sec-check.timer"]
WANTS = {"auto-sec-alert.service": "multi-user.target.wants", "auto-sec-login-watch.service": "multi-user.target.wants",
         "auto-sec-alert.path": "paths.target.wants", "auto-sec-alive.timer": "timers.target.wants",
         "auto-sec-check.timer": "timers.target.wants"}
UNIT_FILES = ["auto-sec-login-watch.service", "auto-sec-alert.service", "auto-sec-alert.path", "auto-sec-alive.timer",
              "auto-sec-alive.service", "auto-sec-check.timer", "auto-sec-check.service", "auto-sec-notify@.service"]


# ---------------------------------------------------------------------- a1
@group
def a1_off(ctx):
    """detection_enabled: false (the default): nothing is read into a plan, nothing changes"""
    lab = Lab(ctx, "a1")
    before = snap(lab.root)
    r = lab.play()
    eq(WHO, "a1 defaults (detection off): the run passes", r.rc, 0)
    check(WHO, "a1 the plan says: off (detection_enabled: false)", r.has("08 detection: off (detection_enabled: false)"), r.n[-600:])
    eq(WHO, "a1 no plan item, nothing to apply", (r.out["plan_08"], r.out["apply"], r.out["do_remove"], r.out["cfg"]), ([], False, False, False))
    eq(WHO, "a1 the report line", r.out["report"], "off (detection_enabled: false): no login alerts from auto_sec on this server")
    eq(WHO, "a1 the lab tree is unchanged", diff(before, snap(lab.root)), [])
    eq(WHO, "a1 systemd was not asked to do anything", lab.calls(), [])
    eq(WHO, "a1 no message was sent", ctx.sink.new(), [])
    r = lab.play({"detection_recon": True})
    check(WHO, "a1 a setting of a later stage (detection_recon) only gets a note (N08-7)",
          r.rc == 0 and r.has("[N08-7] INFO: detection_recon is set, but this release has no such feature yet"), r.n[-400:])


# ---------------------------------------------------------------------- a2
@group
def a2_values(ctx):
    """R08-1, R08-2 and the shape of every value: refused before anything is read"""
    lab = Lab(ctx, "a2")
    before = snap(lab.root)
    base = on(ctx)

    def refused(what, extra, text, drop=()):
        v = dict(base)
        v.update(extra)
        for k in drop:
            v.pop(k, None)
        r = lab.play(v)
        check(WHO, "a2 " + what, r.rc != 0 and r.has(text) and r.has(NOTHING) and r.out is None,
              "rc %s: %s" % (r.rc, r.n[-500:]))

    refused("R08-1: on without a bot token", {}, "[R08-1] detection_enabled is true for localhost, but telegram_bot_token is not set",
            drop=("telegram_bot_token",))
    refused("R08-1: the token is still CHANGE_ME", {"telegram_bot_token": "CHANGE_ME"}, "[R08-1]")
    refused("R08-1: on without a chat id", {}, "but telegram_chat_id is not set", drop=("telegram_chat_id",))
    refused("R08-2: detection_remove together with detection_enabled", {"detection_remove": True}, "[R08-2]")
    refused("detection_enabled: maybe", {"detection_enabled": "maybe"}, "must each be true or false")
    refused("root as a quiet account", {"detection_quiet_accounts": ["root"]}, "detection_quiet_accounts must not hold root")
    refused("quiet accounts as one string", {"detection_quiet_accounts": "auditor"}, "detection_quiet_accounts must be a list")
    refused("a quiet account that is not a name", {"detection_quiet_accounts": ["bad name"]}, "item 1 is not an account name")
    refused("a quiet key that is not a fingerprint", {"detection_quiet_ssh_keys": ["SHA256:short"]}, "item 1 is not a fingerprint")
    refused("a quiet key given as the public key itself",
            {"detection_quiet_ssh_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholderPlacehold lab"]},
            "item 1 is not a fingerprint")
    refused("a label with other characters", {"detection_quiet_ssh_keys": [{"fingerprint": QUIET_FP, "label": "x;y"}]},
            "the label may hold")
    refused("a quiet key with an unknown field", {"detection_quiet_ssh_keys": [{"fingerprint": QUIET_FP, "name": "x"}]},
            "has keys other than fingerprint and label")
    refused("the daily time without a leading zero", {"detection_heartbeat_time": "9:00"}, "detection_heartbeat_time must be a quoted time")
    refused("the daily time unquoted in YAML (09:00 is read as 540)", {"detection_heartbeat_time": 540},
            "detection_heartbeat_time must be a quoted time")
    refused("an undo window that is too short", {"detection_revert_seconds": 60}, "detection_revert_seconds must be a whole number from 120 to 1800")
    eq(WHO, "a2 the lab tree is unchanged after all of them", diff(before, snap(lab.root)), [])
    eq(WHO, "a2 no message was sent", ctx.sink.new(), [])


# ---------------------------------------------------------------------- a3
@group
def a3_ci_switches(ctx):
    """The CI-only switches work only in auto_sec's own CI"""
    lab = Lab(ctx, "a3")
    r = lab.play(on(ctx), ci=False)
    check(WHO, "a3 autosec_ci_detect_api outside GitHub Actions: refused", r.rc != 0 and r.has("autosec_ci_detect_api is set. It is a test switch")
          and r.has(NOTHING), r.n[-400:])
    r = lab.play(on(ctx, autosec_ci=False))
    check(WHO, "a3 autosec_ci_detect_api without autosec_ci: true: refused", r.rc != 0 and r.has("autosec_ci_detect_api is set"), r.n[-400:])
    r = lab.play(on(ctx, autosec_ci_detect_api="http://198.51.100.7:8080"))
    check(WHO, "a3 an address that is not this machine: refused", r.rc != 0 and r.has("autosec_ci_detect_api is set"), r.n[-400:])
    r = lab.play(on(ctx, autosec_ci_detect_api="https://api.telegram.org"))
    check(WHO, "a3 the real Telegram address through the test switch: refused", r.rc != 0 and r.has("autosec_ci_detect_api is set"), r.n[-400:])
    r = lab.play(on(ctx, autosec_ci_inject_pam_fail=True))
    check(WHO, "a3 autosec_ci_inject_pam_fail without its own CI variable: refused",
          r.rc != 0 and r.has("autosec_ci_inject_pam_fail is set. It is a test switch"), r.n[-400:])
    eq(WHO, "a3 no message was sent", ctx.sink.new(), [])


# ---------------------------------------------------------------------- a4
@group
def a4_plan(ctx):
    """The plan of a first install with both sensors (plan only)"""
    lab = Lab(ctx, "plan")
    L = lab.root
    before = snap(L)
    r = lab.play(on(ctx), args=["-e", "autosec_plan_only=true"])
    eq(WHO, "a4 plan only: the run passes", r.rc, 0)
    lines = [
        "08 detection: write: folders, root only (0700): %s/etc/auto-sec, %s/var/spool/auto-sec, %s/var/spool/auto-sec/events, "
        "%s/var/lib/auto-sec/detect" % (L, L, L, L),
        "write: %s/usr/local/sbin/auto-sec-detect" % L,
        "write: %s/usr/local/sbin/auto-sec-login-hook" % L,
        "write: %s/etc/auto-sec/detect.conf (0600): the Telegram token and chat id; quiet accounts: auditor; "
        "quiet SSH keys: auto_sec runs (SHA256:91kT...z+JXR8); daily message at 09:00 server time; login hook and journal reader; "
        "TEST MODE: messages go to %s" % (L, ctx.sink.api),
        "write: %s/etc/systemd/system/auto-sec-alive.timer: daily at 09:00 server time" % L,
        "start: auto-sec-alert.service: the sender (start at boot) (start)",
        "start: auto-sec-login-watch.service: the journal reader (start at boot) (start)",
        "start: auto-sec-alert.path: wakes the sender when an event waits (start at boot) (start)",
        "timer: auto-sec-alive.timer: the daily message (start at boot) (start)",
        "timer: auto-sec-check.timer: the checker, every 5 minutes (start at boot) (start)",
        'write: %s/usr/share/pam-configs/auto-sec-login-alert (the PAM profile, "Default: no")' % L,
        "write: /etc/pam.d/common-session: one line added with pam-auth-update --enable: '%s' (it also updates its own records in /var/lib/pam and in debconf's database); put back after 300 s unless a login test works" % SHOWN,
        "write: %s and /etc/systemd/system/auto-sec-ssh-guard-boot.service (the automatic undo)" % lab.guard,
        "network-call: from now on, from the server to api.telegram.org: a message at every login that is not quiet, one a day at 09:00, "
        "and one when detection stops or has a problem",
        "network-call: one test message now, from the server to api.telegram.org",
        "server: 15 files, 0 packages, 5 services (re)started, 0 firewall rules, 2 outside service(s) called",
        "plan only: nothing changes in this run",
    ] + ["write: %s/etc/systemd/system/%s" % (L, u) for u in UNIT_FILES if u != "auto-sec-alive.timer"]
    missing = [ln for ln in lines if not r.has(ln)]
    eq(WHO, "a4 every line of the plan: folders, 11 files, 5 units, the PAM profile and line, the undo, the calls, the totals", missing, [])
    check(WHO, "a4 the note under the plan: tried on a copy with this server's own pam-auth-update",
          r.has("08 pam: tried on a copy with this server's own pam-auth-update: exactly this one line is added; "
                "cron, plain sudo and services do not read this file"), r.n[-900:])
    check(WHO, "a4 local mode is said (N08-8), an empty quiet list is not (N08-5)", r.has("[N08-8] local mode") and not r.has("[N08-5]"))
    eq(WHO, "a4 the report line", r.out["report"], "not installed yet: this run installs it")
    eq(WHO, "a4 what the preflight planned", (r.out["apply"], r.out["plan"]["pam"], r.out["plan"]["test"], r.out["plan"]["fresh"],
                                              r.out["plan"]["reload"], len(r.out["plan"]["write"])), (True, True, True, True, False, 11))
    eq(WHO, "a4 the lab tree is unchanged", diff(before, snap(L)), [])
    eq(WHO, "a4 nothing was started, no message was sent", (lab.calls(), ctx.sink.new()), ([], []))
    pid = r.plan_id()
    check(WHO, "a4 the plan has an id", bool(pid))
    # The same plan without the test switch (plan only: nothing is sent). Its
    # id does not hold the sink's port, so run.sh can compare it between
    # ansible-core versions.
    plain = {k: val for k, val in on(ctx).items() if k not in ("autosec_ci", "autosec_ci_detect_api")}
    rp = lab.play(plain, args=["-e", "autosec_plan_only=true"], ci=False)
    check(WHO, "a4 the plan as an operator gets it (no test switch): the same lines without TEST MODE",
          rp.rc == 0 and not rp.has("TEST MODE") and rp.has("login hook and journal reader") and bool(rp.plan_id())
          and rp.plan_id() != pid and diff(before, snap(L)) == [], (rp.rc, rp.n[-500:]))
    info(WHO, "plan id a4 = %s" % rp.plan_id())
    r2 = lab.play(on(ctx), args=["-e", "autosec_plan_only=true"])
    eq(WHO, "a4 the same plan gives the same id again", r2.plan_id(), pid)
    r3 = lab.play(on(ctx, detection_quiet_accounts=["auditor", "cve-patcher"]), args=["-e", "autosec_plan_only=true"])
    check(WHO, "a4 another quiet list gives another id", r3.plan_id() not in ("", pid), r3.plan_id())
    r4 = lab.play(on(ctx, detection_quiet_accounts=[], detection_quiet_ssh_keys=[]), args=["-e", "autosec_plan_only=true"])
    check(WHO, "a4 an empty quiet list is said (N08-5): also auto_sec's own logins will send a message",
          r4.rc == 0 and r4.has("[N08-5] the quiet list is empty") and r4.has("quiet accounts: none; quiet SSH keys: none"), r4.n[-600:])
    r5 = lab.play(on(ctx), args=["--check"])
    check(WHO, "a4 --check: passes, says what the real run does, changes nothing",
          r5.rc == 0 and r5.has("Check mode: the real run writes") and r5.has("adds its one line to /etc/pam.d/common-session under the automatic undo")
          and diff(before, snap(L)) == [] and lab.calls() == [] and ctx.sink.new() == [], (r5.rc, diff(before, snap(L)), r5.n[-500:]))
    # the web admin panel
    w = Lab(ctx, "plan-webmin")
    pam.write(w.path("etc/webmin/miniserv.conf"), "port=10000\nsyslog=1\npam=webmin\nsecret=do-not-read-me\n")
    r = w.play(on(ctx), args=["-e", "autosec_plan_only=true"])
    check(WHO, "a4 Webmin installed: said (N08-4), and only two words of its settings were read",
          r.rc == 0 and r.has("[N08-4] Webmin is installed: its logins are read from the journal") and "do-not-read-me" not in r.log, r.n[-500:])
    pam.write(w.path("etc/webmin/miniserv.conf"), "port=10000\nsyslog=0\n")
    r = w.play(on(ctx), args=["-e", "autosec_plan_only=true"])
    check(WHO, "a4 Webmin that does not log to syslog: said plainly", r.rc == 0 and r.has("the journal reader does not see its logins"), r.n[-500:])


# ---------------------------------------------------------------------- a5
@group
def a5_refusals(ctx):
    """The preflight's refusals: each one before any change"""
    def refused(what, lab, extra, texts, args=(), env=None):
        before = snap(lab.root)
        r = lab.play(on(ctx, **extra), args=list(args), env=env)
        texts = [texts] if isinstance(texts, str) else texts
        ok = r.rc != 0 and all(r.has(t) for t in texts) and r.has(NOTHING)
        check(WHO, "a5 " + what, ok, "rc %s: %s" % (r.rc, r.n[-700:]))
        eq(WHO, "a5 ... and the lab tree is unchanged", diff(before, snap(lab.root)), [])
        return r

    # R08-P1: hand edits
    lab = Lab(ctx, "r-p1")
    text = read(lab.path("etc/pam.d/common-session"))
    pam.write(lab.path("etc/pam.d/common-session"), text.replace(pam.END_MARK, "session optional pam_lastlog.so\n" + pam.END_MARK, 1))
    refused("R08-P1: hand edits inside pam-auth-update's block: refused, with the way out", lab, {},
            ["[R08-P1] The common PAM files on localhost have hand edits", "auto_sec does not force it and edits no PAM file itself",
             "Set detection_login_hook: false to run the journal reader only"])
    before = snap(lab.root)
    r = lab.play(on(ctx, detection_login_hook=False), args=["-e", "autosec_plan_only=true"])
    check(WHO, "a5 the way out works on that server: journal reader only plans no PAM change (N08-2)",
          r.rc == 0 and r.has("[N08-2] journal reader only (detection_login_hook: false): no PAM file is touched")
          and not r.has("pam-auth-update --enable") and r.out["plan"]["pam"] is False and "hook" not in r.out["plan"]["write"]
          and r.has("server: 11 files, 0 packages, 5 services (re)started"), r.n[-700:])
    eq(WHO, "a5 ... and the lab tree is unchanged", diff(before, snap(lab.root)), [])

    # R08-P2: a profile of another package waits
    lab = Lab(ctx, "r-p2")
    pam.write(lab.path("usr/share/pam-configs/other"), pam.OTHER_PROFILE)
    refused("R08-P2: a PAM profile of another package is not applied yet", lab, {},
            ["[R08-P2] pam-auth-update on localhost would change", "/etc/pam.d/common-session", "even without auto_sec"])

    # R08-P5: a hook line that auto_sec did not write
    lab = Lab(ctx, "r-p5")
    with open(lab.path("etc/pam.d/common-session"), "a", encoding="utf-8") as fh:
        fh.write("session optional pam_exec.so /usr/local/sbin/auto-sec-login-hook\n")
    refused("R08-P5: a line with the hook's name that auto_sec did not write", lab, {},
            ["[R08-P5] A PAM line on localhost names auto_sec's login hook, but not the way auto_sec writes it",
             "common-session: session optional pam_exec.so /usr/local/sbin/auto-sec-login-hook"])

    # R08-P6: a PAM file would hand a user's own variables to the hook, which runs as root
    lab = Lab(ctx, "r-p6")
    pam.write(lab.path("etc/pam.d/sshd"), pam.STOCK_SERVICES["sshd"])
    pam.write(lab.path("etc/pam.d/panel"), "session required pam_env.so user_readenv=1\n@include common-session\n")
    refused("R08-P6: a PAM service reads a user's own environment file before the common session lines", lab, {},
            ["[R08-P6] On localhost, PAM reads a user's own environment file (pam_env.so user_readenv=1) before the common session lines, in: "
             "panel (session lines).", "auto_sec does not add its hook on such a server",
             "Set detection_login_hook: false to run the journal reader only"])
    os.remove(lab.path("etc/pam.d/panel"))
    r = lab.play(on(ctx), args=["-e", "autosec_plan_only=true"])
    check(WHO, "a5 sshd's own file, as the distributions ship it (it reads that file after the common session lines): no refusal",
          r.rc == 0 and not r.has("[R08-P6]") and r.has("one line added with pam-auth-update --enable"), r.n[-500:])

    # R08-P3: the tools are missing
    lab = Lab(ctx, "r-p3")
    refused("R08-P3: no pam-auth-update", lab, {"_det_pam_tool": lab.path("nonexistent/pam-auth-update")},
            ["[R08-P3] auto_sec cannot add its login hook to PAM on localhost with pam-auth-update",
             "pam-auth-update (libpam-runtime) is not there"])
    os.remove(lab.path("usr/bin/timeout"))
    refused("R08-P3: no /usr/bin/timeout", lab, {}, ["[R08-P3]", "/usr/bin/timeout is not there"])
    lab = Lab(ctx, "r-p3b")
    os.remove(lab.path("etc/pam.d/common-session"))
    os.symlink("common-session-noninteractive", lab.path("etc/pam.d/common-session"))
    refused("R08-P3: a common PAM file is a link", lab, {}, ["[R08-P3]", "/etc/pam.d/common-session is a link, not a plain file"])
    # pam-auth-update ignores an option it does not know: without --root the trial would be a real run
    lab = Lab(ctx, "r-p3c")
    mark = os.path.join(lab.base, "tool-was-started")
    fake = os.path.join(lab.base, "old-pam-auth-update")
    pam.write(fake, "#!/bin/sh\n# stands for a pam-auth-update from before that option\necho started >> '%s'\nexit 0\n" % mark, 0o755)
    refused("R08-P3: a pam-auth-update without a --root option", lab, {"_det_pam_tool": fake},
            ["[R08-P3] auto_sec cannot add its login hook to PAM on localhost with pam-auth-update",
             "this pam-auth-update has no --root option, so the change cannot be tried on a copy first"])
    check(WHO, "a5 ... and that pam-auth-update was never started", not os.path.exists(mark))

    # R08-P7: the trial itself changed the server's own PAM files
    lab = Lab(ctx, "r-p7")
    fake = os.path.join(lab.base, "odd-pam-auth-update")
    pam.write(fake, "#!/bin/sh\n# names '--root' and ignores it\necho '# written behind the trial' >> '%s'\nexit 0\n"
              % lab.path("etc/pam.d/common-session"), 0o755)
    r = lab.play(on(ctx, _det_pam_tool=fake))
    check(WHO, "a5 R08-P7: a pam-auth-update that writes the real files during the trial: the run stops, names the file, "
               "and does not say that nothing changed",
          r.rc != 0 and r.has("[R08-P7] While auto_sec tried its PAM change on a copy, the real files on localhost changed: "
                              "/etc/pam.d/common-session.")
          and r.has("auto_sec stops here, before its own PAM change") and not r.has(NOTHING), "rc %s: %s" % (r.rc, r.n[-700:]))
    check(WHO, "a5 ... and role 08 wrote none of its files", not os.path.exists(lab.path("usr/local/sbin/auto-sec-detect")))

    # R08-3: a file with auto_sec's name that auto_sec did not write
    lab = Lab(ctx, "r-3")
    pam.write(lab.path("etc/systemd/system/auto-sec-alert.service"), "[Unit]\nDescription=mine\n")
    refused("R08-3: a unit file with auto_sec's name and no header line", lab, {"detection_login_hook": False},
            ["[R08-3] %s on localhost is not auto_sec's" % lab.path("etc/systemd/system/auto-sec-alert.service"),
             "auto_sec never replaces or removes a file it did not write"])
    r = lab.play()
    check(WHO, "a5 the same file with detection off: no refusal (nothing would be written)", r.rc == 0 and not r.has("[R08-3]"), r.n[-300:])
    refused("R08-3: also for a removal (-e detection_remove=true)", lab, {"detection_enabled": False, "detection_remove": True},
            "[R08-3]")
    lab = Lab(ctx, "r-3b")
    pam.write(lab.path("usr/lib/systemd/system/auto-sec-check.timer"), "[Timer]\nOnCalendar=daily\n")
    refused("R08-3: a unit with one of auto_sec's names in another unit folder", lab, {"detection_login_hook": False},
            ["[R08-3] %s on localhost is not auto_sec's" % lab.path("usr/lib/systemd/system/auto-sec-check.timer")])
    lab = Lab(ctx, "r-3c")
    os.makedirs(lab.path("etc/auto-sec"))
    os.symlink("/dev/null", lab.path("etc/auto-sec/detect.conf"))
    refused("R08-3: a link where the settings file belongs", lab, {"detection_login_hook": False},
            ["[R08-3] %s on localhost is not auto_sec's" % lab.path("etc/auto-sec/detect.conf")])

    # R08-4: no python3
    lab = Lab(ctx, "r-4")
    refused("R08-4: python3 is missing on the server", lab, {"_det_python": "/nonexistent/python3"},
            ["[R08-4] /nonexistent/python3 is missing on localhost", "auto_sec installs no package for them"])

    # R08-7: an earlier undo is pending
    lab = Lab(ctx, "r-7")
    pam.write(lab.path("var/lib/auto-sec/ssh-guard/pending"), "autosec-000000000001\n")
    refused("R08-7: an earlier change still waits for its automatic undo", lab, {},
            ["[R08-7] An earlier auto_sec change on localhost is still waiting for its automatic undo"])

    # R08-6: the login test needs ssh or local mode
    lab = Lab(ctx, "r-6")
    refused("R08-6: not local mode and not Ansible's ssh connection", lab, {"lab_local_mode": False, "ansible_connection": "local"},
            ["[R08-6] After it adds its login hook to PAM, auto_sec tests a brand-new SSH login", 'ansible_connection "local"'])
    eq(WHO, "a5 no refusal started anything or sent a message", (ctx.sink.new(), [c for lab in ctx.labs for c in lab.calls()]), ([], []))


# ---------------------------------------------------------------------- a6
@group
def a6_tags(ctx):
    """Tags: role 08 reads and plans only when it is selected"""
    lab = Lab(ctx, "tags")
    before = snap(lab.root)
    r = lab.play(on(ctx), args=["--tags", "ssh", "-e", "autosec_plan_only=true"])
    check(WHO, "a6 --tags ssh: role 08 is not selected, nothing is read",
          r.rc == 0 and r.has("08 detection: not selected by --tags") and r.out["role_runs"] is False and r.out["plan_08"] == []
          and r.out["report"] == "not checked in this run (role 08 is not selected by --tags)", (r.rc, r.out, r.n[-400:]))
    r = lab.play(on(ctx), args=["--skip-tags", "detection", "-e", "autosec_plan_only=true"])
    check(WHO, "a6 --skip-tags detection: the same", r.rc == 0 and r.out["role_runs"] is False, (r.rc, r.out))
    r = lab.play(on(ctx), args=["--tags", "detection", "-e", "autosec_plan_only=true"])
    check(WHO, "a6 --tags detection: role 08 plans", r.rc == 0 and r.out["role_runs"] is True and len(r.out["plan_08"]) > 10, (r.rc, r.out))
    r = lab.play({"detection_enabled": True}, args=["--tags", "ssh"])
    check(WHO, "a6 R08-1 stops every run, whatever the tags", r.rc != 0 and r.has("[R08-1]"), r.n[-300:])
    eq(WHO, "a6 the lab tree is unchanged", diff(before, snap(lab.root)), [])


# ---------------------------------------------------------------------- a7
@group
def a7_journal_only(ctx):
    """Journal reader only: approval, a real install into the lab, a second run, changes, a test on demand, removal"""
    lab = Lab(ctx, "journal")
    L = lab.root
    pristine = snap(L)
    pam_before = lab.pam_files()
    v = on(ctx, detection_login_hook=False)

    # approval
    r = lab.play(dict(v, autosec_require_approval=True))
    pid = r.plan_id()
    check(WHO, "a7 with autosec_require_approval the install needs your OK (R00-4), and nothing changes",
          r.rc != 0 and r.has("[R00-4]") and bool(pid) and diff(pristine, snap(L)) == [], (r.rc, pid, diff(pristine, snap(L))))
    r = lab.play(dict(v, autosec_require_approval=True), args=["-e", "autosec_approve=000000000000"])
    check(WHO, "a7 another plan id is refused (R00-5)", r.rc != 0 and r.has("[R00-5]") and diff(pristine, snap(L)) == [], r.rc)

    # the install
    r = lab.play(dict(v, autosec_require_approval=True), args=["-e", "autosec_approve=" + pid])
    if not eq(WHO, "a7 the approved install passes", r.rc, 0):
        info(WHO, "log: " + r.n[-1500:])
        return
    modes = {rel: (stat.S_IMODE(os.lstat(lab.path(rel)).st_mode) if os.path.exists(lab.path(rel)) else None) for rel in
             ["usr/local/sbin/auto-sec-detect", "etc/auto-sec/detect.conf", "etc/auto-sec", "var/spool/auto-sec",
              "var/spool/auto-sec/events", "var/lib/auto-sec/detect"] + ["etc/systemd/system/" + u for u in UNIT_FILES]}
    want = {rel: 0o644 for rel in modes}
    want.update({"usr/local/sbin/auto-sec-detect": 0o700, "etc/auto-sec/detect.conf": 0o600, "etc/auto-sec": 0o700,
                 "var/spool/auto-sec": 0o700, "var/spool/auto-sec/events": 0o700, "var/lib/auto-sec/detect": 0o700})
    eq(WHO, "a7 the program (0700), the settings (0600), four root-only folders and eight unit files (0644) are there", modes, want)
    eq(WHO, "a7 the installed files are byte for byte the role's files",
       [n for n, src in [("usr/local/sbin/auto-sec-detect", "auto-sec-detect")] + [("etc/systemd/system/" + u, u) for u in UNIT_FILES
                                                                                    if u != "auto-sec-alive.timer"]
        if sha(lab.path(n)) != sha(os.path.join(pam.FILES, src))], [])
    eq(WHO, "a7 the login hook is not installed, and no PAM file or record changed",
       (os.path.exists(lab.path("usr/local/sbin/auto-sec-login-hook")), lab.pam_files()), (False, pam_before))
    links = {u: (os.readlink(lab.path("etc/systemd/system/%s/%s" % (WANTS[u], u)))
                 if os.path.islink(lab.path("etc/systemd/system/%s/%s" % (WANTS[u], u))) else None) for u in UNITS}
    eq(WHO, "a7 five links start the units at boot (no systemctl enable)", links, {u: lab.path("etc/systemd/system/" + u) for u in UNITS})
    eq(WHO, "a7 systemd was asked to start the five units in order, and nothing else (no daemon-reload for new unit files)",
       lab.calls(), ["start " + u for u in UNITS])
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(lab.path("etc/auto-sec/detect.conf"))
    eq(WHO, "a7 the settings file holds your values",
       {k: cp.get("detect", k) for k in ("telegram_chat_id", "quiet_accounts", "quiet_ssh_keys", "alive_time", "login_hook", "api_base")},
       {"telegram_chat_id": "-100123", "quiet_accounts": "auditor", "quiet_ssh_keys": QUIET_FP, "alive_time": "09:00",
        "login_hook": "false", "api_base": ctx.sink.api})
    eq(WHO, "a7 its first line is auto_sec's header",
       read(lab.path("etc/auto-sec/detect.conf")).split("\n")[0],
       "# Written by auto_sec (role 08). auto_sec changes this file only while this line is first.")
    check(WHO, "a7 the timer file holds the daily time", "OnCalendar=*-*-* 09:00:00" in read(lab.path("etc/systemd/system/auto-sec-alive.timer")))
    msgs = ctx.sink.new(wait=5)
    m = re.search(r"Check Telegram for auto_sec test ([0-9a-f]{8})", r.n)
    check(WHO, "a7 the run prints the id of its test message, and that message is in the chat",
          bool(m) and len(msgs) == 1 and msgs[0].startswith("auto_sec test %s: alerts from localhost reach this chat." % (m.group(1) if m else "?")),
          (m.group(0) if m else None, msgs))
    check(WHO, "a7 the run says that the message went to the test sink, not to Telegram", r.has("(TEST MODE: it went to the sink on the server, not to Telegram.)"))
    eq(WHO, "a7 the status after the run, for the report",
       (r.after["status"]["verdict"], r.after["report"]),
       ("on", "detection: on, last alive message never (journal reader only); a test message went out in this run"))
    mark = lab.path("run/auto-sec/detect-planned")
    age = time.time() - os.stat(mark).st_mtime if os.path.exists(mark) else -1
    check(WHO, "a7 the mark that keeps stop messages quiet during a run is set to run out 20 s after the run",
          860 < age < 1100, age)
    check(WHO, "a7 the real sender runs against the lab", lab.sender_pid() > 0 and os.path.exists("/proc/%d" % lab.sender_pid()))

    # a login, end to end: a journal line -> the queue -> the sender -> the chat
    lab.event(fixture(kind="accepted", method="password", user="root"))
    msgs = ctx.sink.new(wait=15)
    check(WHO, "a7 a root login with a password, as the journal reader would write it: one message from the installed sender",
          len(msgs) == 1 and "root logged in over SSH with a PASSWORD" in msgs[0] and "203.0.113.5" in msgs[0] and "localhost" in msgs[0], msgs)
    check(WHO, "a7 the message holds no token", all(TOKEN not in t for t in msgs))
    rec = fixture(kind="accepted", method="publickey", user="root", fp=QUIET_FP)
    lab.event(rec)
    time.sleep(4)
    eq(WHO, "a7 a root login with the quiet key: no message", ctx.sink.new(), [])
    eq(WHO, "a7 ... and it is counted", lab.status().get("day", {}).get("quiet"), 1)

    # the daily message, and what the next run says
    lab.detect("alive")
    msgs = ctx.sink.new(wait=15)
    check(WHO, "a7 the daily message goes out with the counts", len(msgs) == 1 and msgs[0].startswith("auto_sec alive: "), msgs)
    installed = snap(L, skip=("var/lib/auto-sec/detect", "var/spool/auto-sec/events"))
    lab.calls()
    r = lab.play(v)
    check(WHO, "a7 the second run: no change, and the plan says 'detection: on, last alive message <time>'",
          r.rc == 0 and r.has("08 detection: no change") and bool(re.search(r"08 detection: detection: on, last alive message 20\d\d-\d\d-\d\d \d\d:\d\d:\d\d UTC", r.n))
          and r.out["plan_08"] == [] and r.out["apply"] is False, (r.rc, r.n[-800:]))
    check(WHO, "a7 the plan says loudly that this is the test sink", r.has("TEST MODE: messages go to a sink on the server itself, not to Telegram"))
    check(WHO, "a7 the report line of that run", re.fullmatch(r"detection: on, last alive message 20[0-9: -]+ UTC \(journal reader only\)", r.after["report"]) is not None,
          r.after["report"])
    eq(WHO, "a7 the second run wrote nothing, started nothing, sent nothing",
       (diff(installed, snap(L, skip=("var/lib/auto-sec/detect", "var/spool/auto-sec/events"))), lab.calls(), ctx.sink.new()), ([], [], []))

    # a changed setting
    r = lab.play(dict(v, detection_quiet_accounts=["auditor", "cve-patcher"]))
    check(WHO, "a7 a new quiet account: the plan replaces the settings and restarts the sender and the reader",
          r.rc == 0 and r.has("08 detection: replace: %s/etc/auto-sec/detect.conf (0600)" % L) and r.has("quiet accounts: auditor, cve-patcher")
          and r.has("restart: auto-sec-alert.service: the sender (restart)") and r.has("restart: auto-sec-login-watch.service: the journal reader (restart)")
          and not r.has("daemon-reload: systemd"), (r.rc, r.n[-900:]))
    eq(WHO, "a7 ... systemd restarted those two, nothing else", lab.calls(), ["restart auto-sec-alert.service", "restart auto-sec-login-watch.service"])
    eq(WHO, "a7 ... a test message went out, and no 'the watcher was stopped' message", [t[:13] for t in ctx.sink.new(wait=5)], ["auto_sec test"])
    v2 = dict(v, detection_quiet_accounts=["auditor", "cve-patcher"], detection_heartbeat_time="07:30", detection_test_alert=False)
    open(os.path.join(lab.sd, "pending"), "w").close()
    r = lab.play(v2)
    check(WHO, "a7 R08-5: a changed unit file needs a daemon-reload, which would load unit edits of yours: refused",
          r.rc != 0 and r.has("[R08-5] localhost has unit edits systemd has not loaded yet: lab-edited.service") and r.has(NOTHING), (r.rc, r.n[-500:]))
    os.remove(os.path.join(lab.sd, "pending"))
    lab.calls()
    ctx.sink.new()
    r = lab.play(v2)
    check(WHO, "a7 a new daily time: the timer file is replaced, with a daemon-reload, and no test message when detection_test_alert is false",
          r.rc == 0 and r.has("replace: %s/etc/systemd/system/auto-sec-alive.timer: daily at 07:30 server time" % L)
          and r.has("daemon-reload: systemd (a detection unit file changes)") and r.has("timer: auto-sec-alive.timer: the daily message (restart)")
          and not r.has("one test message now"), (r.rc, r.n[-900:]))
    eq(WHO, "a7 ... daemon-reload first, then the restarts",
       lab.calls(), ["daemon-reload", "restart auto-sec-alert.service", "restart auto-sec-login-watch.service", "restart auto-sec-alive.timer"])
    check(WHO, "a7 ... the timer file holds the new time", "OnCalendar=*-*-* 07:30:00" in read(lab.path("etc/systemd/system/auto-sec-alive.timer")))
    eq(WHO, "a7 ... no message", ctx.sink.new(wait=2, want=1), [])

    # a test message on demand
    r = lab.play(dict(v2, detection_test_alert=True))
    m = re.search(r"Check Telegram for auto_sec test ([0-9a-f]{8})", r.n)
    msgs = ctx.sink.new(wait=5)
    check(WHO, "a7 -e detection_test_alert=true on a run that changes nothing else: one test message, its id printed",
          r.rc == 0 and bool(m) and len(msgs) == 1 and (m.group(1) if m else "?") in msgs[0]
          and r.has("08 detection: network-call: one test message now") and lab.calls() == [], (r.rc, msgs, r.n[-500:]))

    # off again: nothing is removed
    r = lab.play({"detection_enabled": False, "telegram_bot_token": TOKEN, "telegram_chat_id": "-100123"})
    check(WHO, "a7 detection_enabled: false on an installed server removes nothing, and says how to remove (N08-1)",
          r.rc == 0 and r.has("08 detection: no change") and r.has("[N08-1] login alerts of an earlier run stay on this server and keep working")
          and r.after["report"].endswith("; detection_enabled is false, and that removes nothing") and lab.calls() == [], (r.rc, r.n[-700:]))

    # dead
    sender = lab.sender_pid()
    os.kill(sender, signal.SIGKILL)
    os.remove(os.path.join(lab.sd, "unit.auto-sec-alert.service"))
    old = time.time() - 3600
    os.utime(lab.path("var/lib/auto-sec/detect/sender.alive"), (old, old))
    r = lab.play(v2, args=["-e", "autosec_plan_only=true"])
    check(WHO, "a7 the sender is gone: the plan says 'detection: DEAD since <time>' (W08-2) and plans to start it",
          r.rc == 0 and bool(re.search(r"\[W08-2\] WARNING: detection: DEAD since 20\d\d-\d\d-\d\d \d\d:\d\d:\d\d UTC \(the sender is not running", r.n))
          and r.has("08 detection: start: auto-sec-alert.service: the sender (start)") and r.out["status"]["verdict"] == "dead"
          and r.out["report"].startswith("detection: DEAD since 20"), (r.rc, r.out and r.out["report"], r.n[-900:]))
    run_out(lab)
    c = lab.detect("check")
    msgs = ctx.sink.new(wait=5)
    check(WHO, "a7 the independent checker says so in the chat by itself (it does not need the sender)",
          len(msgs) == 1 and msgs[0].startswith("auto_sec detection problem: localhost") and "the sender is not running" in msgs[0]
          and "repeats every hour" in msgs[0], (c.returncode, msgs))
    run_out(lab)
    lab.detect("check")
    eq(WHO, "a7 ... once, not at every check", ctx.sink.new(wait=2), [])
    r = lab.play(v2)
    check(WHO, "a7 the next run starts it again: detection is on", r.rc == 0 and r.after["status"]["verdict"] == "on"
          and lab.calls() == ["start auto-sec-alert.service"], (r.rc, r.after, r.n[-600:]))
    run_out(lab)
    lab.detect("check")
    msgs = ctx.sink.new(wait=5)
    check(WHO, "a7 ... and the checker says that it works again", len(msgs) == 1 and msgs[0].startswith("auto_sec detection is working again on localhost"), msgs)

    # a unit stops: silent in the 20 s after an auto_sec run restarted units, a message after that
    t = time.time() - 880                     # the file time the role gives the mark when it is done
    os.utime(mark, (t, t))
    s = lab.detect("stopped", "auto-sec-alert.path")
    eq(WHO, "a7 a detection unit stops within 20 s of the run that restarted units: no stop message", (s.returncode, ctx.sink.new(wait=2)), (0, []))
    t = time.time() - 901
    os.utime(mark, (t, t))
    s = lab.detect("stopped", "auto-sec-login-watch.service", "exit-code")
    msgs = ctx.sink.new(wait=5)
    check(WHO, "a7 a detection unit stops outside an auto_sec run: the stop message goes out",
          s.returncode == 0 and len(msgs) == 1 and msgs[0].startswith("auto_sec: the watcher on localhost was stopped.")
          and "auto-sec-login-watch.service (exit-code)" in msgs[0], msgs)

    # removal
    off = {"detection_enabled": False, "detection_remove": True, "telegram_bot_token": TOKEN, "telegram_chat_id": "-100123"}
    before = snap(L)
    lab.calls()
    r = lab.play(off, args=["-e", "autosec_plan_only=true"])
    lines = (["08 detection: network-call: one last message, from the server to api.telegram.org: login alerts are being taken out"]
             + ["stop: " + u for u in UNITS]
             + ["remove: %s/etc/systemd/system/%s/%s (a link)" % (L, WANTS[u], u) for u in UNITS]
             + ["remove: %s/etc/systemd/system/%s" % (L, u) for u in UNIT_FILES]
             + ["remove: %s/usr/local/sbin/auto-sec-detect" % L, "remove: %s/etc/auto-sec/detect.conf" % L,
                "remove: auto_sec's own files in %s/var/spool/auto-sec/events and %s/var/lib/auto-sec/detect, then the folders that are empty: "
                "%s/etc/auto-sec, %s/var/spool/auto-sec, %s/var/spool/auto-sec/events, %s/var/lib/auto-sec/detect" % (L, L, L, L, L, L),
                "daemon-reload: systemd (the detection units are gone)",
                "server: 0 files, 0 packages, 1 services (re)started, 0 firewall rules, 1 outside service(s) called, 16 removed, 5 unit(s) stopped"])
    eq(WHO, "a7 removal, plan only: every link, file and folder that goes is listed, and nothing of PAM",
       ([ln for ln in lines if not r.has(ln)], r.has("pam-auth-update --remove"), r.rc), ([], False, 0))
    eq(WHO, "a7 ... and the plan changed nothing", (diff(before, snap(L, )), lab.calls(), ctx.sink.new()), ([], [], []))
    r = lab.play(off)
    if not eq(WHO, "a7 the removal passes", r.rc, 0):
        info(WHO, "log: " + r.n[-1500:])
        return
    msgs = ctx.sink.new(wait=5)
    check(WHO, "a7 one last message says that login alerts are being taken out",
          len(msgs) == 1 and msgs[0].startswith("auto_sec: login alerts are being taken out of localhost by an auto_sec run"), msgs)
    eq(WHO, "a7 systemd: the units stopped, then daemon-reload",
       lab.calls(), ["stop " + " ".join(reversed(UNITS)) + " auto-sec-alive.service auto-sec-check.service", "daemon-reload",
                     "reset-failed auto-sec-notify@*.service"])
    check(WHO, "a7 the sender is gone", not os.path.exists("/proc/%d" % lab.sender_pid()) if lab.sender_pid() else True)
    left = diff(pristine, snap(L))
    eq(WHO, "a7 after the removal the lab tree is as it was before the install, but for two empty folders others may share",
       left, ["etc/systemd/system/paths.target.wants", "var/lib/auto-sec"])
    eq(WHO, "a7 ... and the PAM files were never touched", lab.pam_files(), pam_before)
    eq(WHO, "a7 the report line", r.after["report"], "taken out by this run (-e detection_remove=true)")
    r = lab.play(off)
    check(WHO, "a7 a second removal run: nothing to do, and it says so",
          r.rc == 0 and r.has("08 detection: no change") and r.has("removal: nothing of auto_sec's detection is on this server")
          and lab.calls() == [] and ctx.sink.new() == [], (r.rc, r.n[-500:]))
    r = lab.play({"detection_enabled": False, "detection_test_alert": True})
    check(WHO, "a7 a test message asked for where nothing is installed: said, not sent",
          r.rc == 0 and r.has("a test message was asked for (-e detection_test_alert=true), but login alerts are not installed on this server")
          and ctx.sink.new() == [], (r.rc, r.n[-500:]))


# ---------------------------------------------------------------------- a8
@group
def a8_hook(ctx):
    """Both sensors: the PAM change under the real undo guard, with the release's real pam-auth-update"""
    for release in ("noble", "jammy"):
        who = "role-" + release
        lab = Lab(ctx, "hook-" + release, release)
        L = lab.root
        pristine = snap(L)
        pam_before = lab.pam_files()
        v = on(ctx)
        if lab.tree.reads_first:
            r = lab.play(v, args=["-e", "autosec_plan_only=true"])
            check(who, "a8 this pam-auth-update cannot try a new profile on a copy: the plan says so (N08-6) and still lists the PAM change",
                  r.rc == 0 and r.has("[N08-6] NOTE: pam-auth-update on localhost reads its profiles before its --root option")
                  and r.has("08 pam: this server's pam-auth-update cannot try a new profile on a copy")
                  and r.has("one line added with pam-auth-update --enable"), (r.rc, r.n[-900:]))
        r = lab.play(v)
        if not eq(who, "a8 the install with the login hook passes", r.rc, 0):
            info(who, "log: " + r.n[-2500:])
            continue
        sess = lab.session()
        eq(who, "a8 common-session holds auto_sec's one line, once, and the hook file is in place (0700)",
           (sess.count(LINE), stat.S_IMODE(os.stat(lab.path("usr/local/sbin/auto-sec-login-hook")).st_mode)), (1, 0o700))
        now = lab.pam_files()
        eq(who, "a8 only common-session, pam-auth-update's two records and the new profile changed",
           sorted(k for k in now if now[k] != pam_before[k]),
           ["etc/pam.d/common-session", "usr/share/pam-configs/" + NAME, "var/lib/pam/seen", "var/lib/pam/session"])
        eq(who, "a8 the profile is the role's file (0644)",
           (sha(lab.path("usr/share/pam-configs/" + NAME)), stat.S_IMODE(os.stat(lab.path("usr/share/pam-configs/" + NAME)).st_mode)),
           (sha(pam.PROFILE), 0o644))
        g = lab.guard_calls()
        gdir = lab.path("var/lib/auto-sec/ssh-guard")
        eq(who, "a8 the real undo guard was armed for a PAM change with a timer, on the 11 PAM files and the profile, then disarmed",
           (len([c for c in g if c.startswith("systemd-run ") and " revert autosec-" in c]), os.path.exists(gdir + "/run/pam"),
            read(gdir + "/run/count").strip(), read(gdir + "/run/result").split()[0], os.path.exists(gdir + "/pending")),
           (1, True, "12", "disarmed", False))
        st = {}
        end = time.monotonic() + 15
        while time.monotonic() < end:
            st = lab.status()
            if st.get("day", {}).get("by_root") == 1:
                break
            time.sleep(0.5)
        kept = json.loads(read(lab.path("var/lib/auto-sec/detect/pam-before.json")))
        eq(who, "a8 the checksums of the PAM files from before the install are kept on the server (0600)",
           (kept, stat.S_IMODE(os.stat(lab.path("var/lib/auto-sec/detect/pam-before.json")).st_mode)),
           ({"/" + k: h for k, h in pam_before.items() if "pam-configs" not in k}, 0o600))
        eq(who, "a8 detection is on with both sensors, and the login test's own event came through the hook's queue",
           (st.get("verdict"), st.get("mode"), st.get("problems"), st.get("last_hook", 0) > time.time() - 300,
            st.get("day", {}).get("by_root")), ("on", "hook+journal", [], True, 1))
        msgs = ctx.sink.new(wait=5)
        eq(who, "a8 one test message, and no alert for the run's own login test (su by root)", [t[:13] for t in msgs], ["auto_sec test"])
        check(who, "a8 the report line", r.after["report"].endswith("(login hook and journal reader); a test message went out in this run"),
              r.after["report"])
        lab.calls()
        installed = snap(L, skip=("var/lib/auto-sec/detect", "var/spool/auto-sec/events", "var/lib/auto-sec/ssh-guard"))
        r = lab.play(v)
        check(who, "a8 the second run changes nothing (the trial says the line is already there)",
              r.rc == 0 and r.has("08 detection: no change") and lab.calls() == [] and ctx.sink.new() == []
              and diff(installed, snap(L, skip=("var/lib/auto-sec/detect", "var/spool/auto-sec/events", "var/lib/auto-sec/ssh-guard"))) == [],
              (r.rc, r.n[-600:]))
        r = lab.play(dict(v, detection_login_hook=False), args=["-e", "autosec_plan_only=true"])
        check(who, "a8 detection_login_hook: false afterwards removes nothing: the hook stays in PAM and keeps working (N08-2)",
              r.rc == 0 and r.has("[N08-2] detection_login_hook is false, but the login hook of an earlier run is still in PAM and keeps working")
              and r.has("08 detection: no change"), (r.rc, r.n[-600:]))

        # the checker notices a PAM line that went away
        text = read(lab.path("etc/pam.d/common-session"))
        pam.write(lab.path("etc/pam.d/common-session"), text.replace(LINE + "\n", ""))
        run_out(lab)
        lab.detect("check")
        msgs = ctx.sink.new(wait=5)
        check(who, "a8 someone takes the hook's line out of PAM: the checker says so in the chat",
              len(msgs) == 1 and "the login hook's line is no longer in /etc/pam.d/common-session" in msgs[0], msgs)
        pam.write(lab.path("etc/pam.d/common-session"), text)
        run_out(lab)
        lab.detect("check")
        ctx.sink.new(wait=5)

        # removal: byte for byte
        off = {"detection_enabled": False, "detection_remove": True, "telegram_bot_token": TOKEN, "telegram_chat_id": "-100123"}
        r = lab.play(off, args=["-e", "autosec_plan_only=true"])
        check(who, "a8 removal, plan only: the PAM line, the profile and the undo are listed, and the note promises byte for byte",
              r.rc == 0 and r.has("write: /etc/pam.d/common-session: auto_sec's line taken out with pam-auth-update --remove (it also updates its own records in /var/lib/pam and in debconf's database); put back after 300 s unless a login test works")
              and r.has("remove: %s/usr/share/pam-configs/%s" % (L, NAME))
              and r.has("08 pam: tried on a copy: exactly auto_sec's line goes; after that the common PAM files are byte for byte as they were before detection was installed")
              and r.has("18 removed, 5 unit(s) stopped"), (r.rc, r.n[-1200:]))
        lab.guard_calls()
        r = lab.play(off)
        if not eq(who, "a8 the removal passes", r.rc, 0):
            info(who, "log: " + r.n[-2500:])
            continue
        eq(who, "a8 after the removal the common PAM files and pam-auth-update's records are byte for byte what they were before the install",
           lab.pam_files(), pam_before)
        left = diff(pristine, snap(L, skip=("var/lib/auto-sec/ssh-guard",)))
        eq(who, "a8 and the lab tree is as before, but for two empty folders others may share and the undo guard's own state",
           left, ["etc/systemd/system/paths.target.wants", "var/lib/auto-sec"])
        check(who, "a8 the result says it", r.has("Login alerts are out of localhost. PAM: tried on a copy: exactly auto_sec's line goes; after that the common PAM files are byte for byte as they were before detection was installed"),
              r.n[-700:])
        eq(who, "a8 the last message went out", [t[:42] for t in ctx.sink.new(wait=5)], ["auto_sec: login alerts are being taken out"])
        lab.calls()


# ---------------------------------------------------------------------- a9
@group
def a9_undo(ctx):
    """The PAM change is undone when a login test fails, when the result is not what the trial showed, and on CI's injected failure"""
    def failing(name, what, extra, env, texts):
        lab = Lab(ctx, name)
        pam_before = lab.pam_files()
        if callable(extra):
            extra = extra(lab)
        r = lab.play(on(ctx, **extra), env=env)
        texts = [texts] if isinstance(texts, str) else texts
        check(WHO, "a9 %s: the run stops and says that the files are back" % what,
              r.rc != 0 and all(r.has(t) for t in texts)
              and r.has("auto_sec put the common PAM files, /var/lib/pam and its profile back as they were before this step"),
              (r.rc, r.n[-1200:]))
        eq(WHO, "a9 ... the common PAM files and records are byte for byte as before, and the profile is gone again", lab.pam_files(), pam_before)
        res = lab.path("var/lib/auto-sec/ssh-guard/run/result")
        eq(WHO, "a9 ... the real undo guard reverted, and nothing is pending",
           (read(res).split()[0] if os.path.exists(res) else None, os.path.exists(lab.path("var/lib/auto-sec/ssh-guard/pending"))),
           ("reverted", False))
        st = lab.status()
        check(WHO, "a9 ... the journal reader and the sender stay installed and on; the status names the missing hook line",
              st.get("verdict") == "on" and any("the login hook's line is no longer in /etc/pam.d/common-session" in p for p in st.get("problems", [])), st)
        ctx.sink.new(wait=1)
        return lab

    failing("undo-su", "the login test (su) fails", {}, {"LAB_SU_RC": "1"}, "[M08-4] A login test failed on localhost after the PAM change: su on the server: rc 1")
    # (lab) the real pam-auth-update is pointed at another tree, so this lab's files stay as they were
    other = Lab(ctx, "undo-m083-elsewhere")
    lab = failing("undo-m083", "pam-auth-update did not write what the trial showed",
                  {"_det_pam_real_args": ["--root", other.root]}, {},
                  ["[M08-3] After pam-auth-update on localhost", "not what the trial showed"])
    failing("undo-inject", "CI's injected failure (autosec_ci_inject_pam_fail)", {"autosec_ci_inject_pam_fail": True},
            {"AUTOSEC_CI_INJECT_FAILURE": "pam"}, ["[M08-4]", "injected by autosec_ci_inject_pam_fail (CI only)"])
    # after a failed PAM step the next run tries again and succeeds
    r = lab.play(on(ctx))
    check(WHO, "a9 the next run plans only the PAM change and a test message, and makes it",
          r.rc == 0 and lab.session().count(LINE) == 1 and lab.status().get("problems") == []
          and not r.has("write: %s/usr/local/sbin/auto-sec-detect" % lab.root), (r.rc, r.n[-900:]))
    ctx.sink.new(wait=3)

    # M08-1: a file changes between the plan and the apply phase
    lab = Lab(ctx, "m081")
    planted = lab.path("etc/systemd/system/auto-sec-alert.path")
    r = lab.play(on(ctx, detection_login_hook=False), env={"LAB_ON_SHOW": "echo planted > '%s'" % planted})
    check(WHO, "a9 M08-1: a file with auto_sec's name appears after the plan was made: role 08 writes nothing",
          r.rc != 0 and r.has("[M08-1] A file of auto_sec's login alerts on localhost changed during this run")
          and not os.path.exists(lab.path("etc/auto-sec")) and not os.path.exists(lab.path("usr/local/sbin/auto-sec-detect"))
          and read(planted) == "planted\n" and lab.calls() == [], (r.rc, r.n[-600:]))


# --------------------------------------------------------------------- a10
@group
def a10_changes_since(ctx):
    """A removal says so when the PAM files are no longer what they were before the install"""
    lab = Lab(ctx, "since")
    r = lab.play(on(ctx))
    if not eq(WHO, "a10 an install with the hook", r.rc, 0):
        info(WHO, "log: " + r.n[-1500:])
        return
    ctx.sink.new(wait=3)
    # another package's profile comes and is applied by its own postinst
    pam.write(lab.path("usr/share/pam-configs/other"), pam.OTHER_PROFILE)
    p = lab.tree.pau("--package")
    check(WHO, "a10 (lab) another package's PAM profile is applied after the install", p.returncode == 0 and "pam_other.so" in read(lab.path("etc/pam.d/common-session")))
    off = {"detection_enabled": False, "detection_remove": True, "telegram_bot_token": TOKEN, "telegram_chat_id": "-100123"}
    r = lab.play(off, args=["-e", "autosec_plan_only=true"])
    check(WHO, "a10 the removal's note: NOT as before the install, and which files changed by something else",
          r.rc == 0 and r.has("after that the common PAM files are NOT as they were before detection was installed (/etc/pam.d/common-session, "
                              "/etc/pam.d/common-session-noninteractive, /var/lib/pam/seen, /var/lib/pam/session, "
                              "/var/lib/pam/session-noninteractive changed since, by something else)"),
          (r.rc, r.n[-900:]))
    r = lab.play(off)
    sess = lab.session()
    check(WHO, "a10 the removal takes out auto_sec's line and leaves the other package's",
          r.rc == 0 and sess.count(LINE) == 0 and any("pam_other.so" in x for x in sess) and not os.path.exists(lab.path("usr/share/pam-configs/" + NAME)),
          (r.rc, r.n[-900:]))
    ctx.sink.new(wait=3)

    # journal reader only first, the hook later
    lab = Lab(ctx, "later")
    r = lab.play(on(ctx, detection_login_hook=False))
    ctx.sink.new(wait=3)
    lab.calls()
    r = lab.play(on(ctx))
    check(WHO, "a10 journal reader only first, the login hook in a later run: the hook file, the settings and the PAM line are planned and made",
          r.rc == 0 and r.has("08 detection: write: %s/usr/local/sbin/auto-sec-login-hook" % lab.root)
          and r.has("replace: %s/etc/auto-sec/detect.conf" % lab.root) and r.has("one line added with pam-auth-update --enable")
          and lab.session().count(LINE) == 1 and lab.status().get("mode") == "hook+journal" and lab.status().get("verdict") == "on",
          (r.rc, r.n[-900:]))
    eq(WHO, "a10 ... the sender and the reader were restarted for the new settings", lab.calls(), ["restart auto-sec-alert.service", "restart auto-sec-login-watch.service"])
    ctx.sink.new(wait=3)


# --------------------------------------------------------------------- a11
@group
def a11_secrets(ctx):
    """The token is in no output"""
    lab = Lab(ctx, "vvv")
    r = lab.play(on(ctx, detection_login_hook=False), args=["-vvv", "--diff"])
    eq(WHO, "a11 an install with -vvv --diff passes", r.rc, 0)
    ctx.sink.new(wait=3)
    check(WHO, "a11 the Telegram token is in no output of any run of this suite (%d runs, also -vvv --diff)" % len(ctx.logs),
          all(TOKEN not in log and TOKEN.split(":")[1] not in log for log in ctx.logs))
    check(WHO, "a11 it is in the settings file on the server, and only there",
          TOKEN in read(lab.path("etc/auto-sec/detect.conf"))
          and [rel for rel, (kind, _m, _h) in snap(lab.root).items() if kind == "file" and rel != "etc/auto-sec/detect.conf"
               and TOKEN.encode() in open(lab.path(rel), "rb").read()] == [])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ansible", required=True)
    ap.add_argument("--x", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    shutil.rmtree(a.work, ignore_errors=True)
    os.makedirs(a.work)
    v = subprocess.run([a.ansible, "--version"], capture_output=True, text=True, check=False).stdout.split("\n")[0]
    info(WHO, v)
    ctx = Ctx(a)
    try:
        for fn in GROUPS:
            if a.only and not any(fn.__name__.startswith(o) for o in a.only.split(",")):
                continue
            try:
                fn(ctx)
            except Exception:  # noqa: BLE001 - one broken group must not hide the others
                check(WHO, "%s: the checks of this group ran to the end" % fn.__name__, False, traceback.format_exc()[-900:])
    finally:
        ctx.close()
    print("test_role: %d passed, %d failed" % (pam.COUNT["pass"], pam.COUNT["fail"]))
    return 1 if pam.COUNT["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
