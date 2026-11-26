#!/usr/bin/env python3
"""test_pam.py - the PAM side of role 08 against the real code of pinned packages.

LAB ONLY (tests/detection/semantics/run.sh). No root, nothing installed:
run.sh has unpacked the pinned .debs (dpkg-deb -x and -e) under --x, as
<x>/<set>/<package>/root and <x>/<set>/<package>/control.

  s   the one PAM line is the same in the profile, the role's constant and
      auto-sec-detect
  m   each release's real pam_exec.so, loaded by this machine's libpam
      through pam_start_confdir() (pamlab.py), with the profile's own
      module line and the real login hook: the event file; a hook that is
      missing, fails or hangs never fails or holds up the session; why the
      time limit is on the PAM line itself; odd PAM values
  t   each release's own pam-auth-update (a Perl script) on lab trees,
      through role 08's trial helper (roles/08-detection/files/
      auto-sec-pam-check): what the helper answers for a pristine tree,
      hand edits, a waiting profile of another package, a foreign hook
      line; that it writes nothing; that the real run gives exactly the
      files the trial showed; that a removal gives every file back byte
      for byte; an older profile of auto_sec's own is replaced

Lab-only changes to a COPY of each pam-auth-update: the path of its debconf
templates and of the pristine common-* files point into the unpacked
package. Ubuntu 22.04's script reads /usr/share/pam-configs before it reads
its --root option; its copy reads the lab tree's folder instead, which is
what "the host's own folder" is in the lab.

Usage: test_pam.py --x DIR --work DIR
Prints one PASS or FAIL line per check; exit 1 when one fails.
"""
import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILES = os.path.join(REPO, "roles", "08-detection", "files")
HOOK = os.path.join(FILES, "auto-sec-login-hook")
PROFILE = os.path.join(FILES, "auto-sec-login-alert")
HELPER = os.path.join(FILES, "auto-sec-pam-check")
DETECT = os.path.join(FILES, "auto-sec-detect")
DEFAULTS = os.path.join(REPO, "roles", "08-detection", "defaults", "main.yml")
PAMLAB = os.path.join(HERE, "pamlab.py")
NAME = "auto-sec-login-alert"
REAL_HOOK = "/usr/local/sbin/auto-sec-login-hook"
QLINE = "Q=/var/spool/auto-sec/events"

COUNT = {"pass": 0, "fail": 0}


def check(who, what, ok, detail=""):
    COUNT["pass" if ok else "fail"] += 1
    print("%s  %-9s %s%s" % ("PASS" if ok else "FAIL", who, what, "" if ok or not detail else ": " + str(detail)[:600]))
    sys.stdout.flush()
    return ok


def eq(who, what, got, want):
    return check(who, what, got == want, "got %r, want %r" % (got, want))


def info(who, what):
    print("INFO  %-9s %s" % (who, what))


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, mode)


def module_line():
    """The profile's one module line: '\\toptional\\tpam_exec.so ...'."""
    lines = [ln for ln in read(PROFILE).split("\n") if ln.startswith("\t")]
    if len(lines) != 1:
        raise SystemExit("the profile must hold exactly one module line")
    return lines[0]


LINE = "session" + module_line()
# The helper shows a line with its tabs turned into spaces.
SHOWN = LINE.replace("\t", " ")
OLD_SHOWN = "session optional pam_exec.so quiet " + REAL_HOOK


# ------------------------------------------------------------------ s: static
def static_checks():
    text = read(DEFAULTS)
    eq("static", "s1 the role's _det_pam_line is the line pam-auth-update writes from the profile",
       '_det_pam_line: "%s"' % LINE.replace("\t", "\\t") in text, True)
    eq("static", "s2 the line shown in the plan is the same line with spaces",
       '_det_pam_line_shown: "%s"' % LINE.replace("\t", " ") in text, True)
    loader = importlib.machinery.SourceFileLoader("auto_sec_detect_for_pam", DETECT)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    loader.exec_module(mod)
    eq("static", "s3 auto-sec-detect looks for the same line", mod.PAM_LINE, LINE)
    eq("static", "s4 auto-sec-detect and the helper know the profile's header line",
       (mod.PROFILE_HEADER, mod.PROFILE_HEADER in read(HELPER)), (read(PROFILE).split("\n")[0], True))
    eq("static", "s5 the line names the hook's real path and a 1 second limit that cannot be ignored",
       LINE.endswith(" /usr/bin/timeout -s KILL 1 " + REAL_HOOK), True)


# ----------------------------------------------------------------- m: pam_exec
def find(root, name):
    for d, _dirs, names in os.walk(root):
        if name in names:
            return os.path.join(d, name)
    return ""


def fields(path):
    with open(path, "rb") as fh:
        data = fh.read()
    out = {}
    for part in data.split(b"\0"):
        if b"=" in part:
            k, v = part.split(b"=", 1)
            out[k.decode()] = v
    return out, data


def pamlab(confdir, service="sshd", user="root", limit=30, **items):
    cmd = [sys.executable, "-I", PAMLAB, "--confdir", confdir, "--service", service, "--user", user]
    for k, v in items.items():
        if v:
            cmd += ["--" + k, v]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=limit, check=False)
    except subprocess.TimeoutExpired:
        return {"waiting": True}
    try:
        return json.loads(p.stdout.strip().split("\n")[-1])
    except (ValueError, IndexError):
        return {"error": (p.stdout + p.stderr)[-300:]}


def gone(pidfile, wait=1.5):
    """True when the process whose pid is in pidfile is gone (or never started)."""
    try:
        pid = int(read(pidfile).strip())
    except (OSError, ValueError):
        return True
    end = time.monotonic() + wait
    while time.monotonic() < end:
        if not os.path.exists("/proc/%d" % pid):
            return True
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    return False


def pam_exec_checks(xdir, work, name):
    who = name
    module = find(os.path.join(xdir, name, "libpam-modules", "root"), "pam_exec.so")
    permit = find(os.path.join(xdir, name, "libpam-modules", "root"), "pam_permit.so")
    if not module or not permit:
        check(who, "m0 pam_exec.so and pam_permit.so are in the unpacked libpam-modules", False, "not found")
        return
    probe = subprocess.run([sys.executable, "-I", "-c", "import ctypes, sys; ctypes.CDLL(sys.argv[1])", module],
                           capture_output=True, text=True, check=False)
    if not check(who, "m0 this machine can load the release's pam_exec.so", probe.returncode == 0, probe.stderr[-200:]):
        return
    lab = os.path.join(work, "m-" + name)
    queue = os.path.join(lab, "q")
    conf = os.path.join(lab, "pam.d")
    os.makedirs(queue, mode=0o700)
    os.makedirs(conf)
    hook = os.path.join(lab, "bin", "auto-sec-login-hook")
    body = read(HOOK)
    if body.count("\n" + QLINE + "\n") != 1:
        raise SystemExit("the hook must hold its queue path exactly once")
    write(hook, body.replace("\n" + QLINE + "\n", "\nQ=" + queue + "\n"), 0o755)
    control, rest = module_line().split("\t")[1:3]
    args = rest.split(" ", 1)[1]            # everything after "pam_exec.so"

    def service(command_args, svc="sshd"):
        write(os.path.join(conf, svc), "session\trequired\t%s\nsession\t%s\t%s %s\n" % (permit, control, module, command_args))

    def events():
        return sorted(os.listdir(queue))

    def clear():
        for n in events():
            os.remove(os.path.join(queue, n))

    # m1: the profile's own line, the real hook
    service(args.replace(REAL_HOOK, hook))
    r = pamlab(conf, tty="ssh", rhost="203.0.113.5")
    eq(who, "m1 a session opens and closes (PAM_SUCCESS)", (r.get("start"), r.get("open"), r.get("close")), (0, 0, 0))
    names = events()
    if eq(who, "m1 one event file after a session opened and closed (nothing is written at close)", len(names), 1):
        f, data = fields(os.path.join(queue, names[0]))
        eq(who, "m1 the event holds what PAM knew",
           (f.get("svc"), f.get("user"), f.get("tty"), f.get("rhost"), f.get("src")), (b"sshd", b"root", b"ssh", b"203.0.113.5", b"hook"))
        eq(who, "m1 app is the process that opened the session (not timeout, not pam_exec's child)",
           f.get("app"), str(r.get("pid")).encode())
        eq(who, "m1 ruid is that process's real uid", f.get("ruid"), str(os.getuid()).encode())
        check(who, "m1 the event is complete (ends with end=1)", data.endswith(b"\0end=1\0"))
    check(who, "m1 the hook costs a login less than 0.5 s (%s ms)" % r.get("open_ms"), (r.get("open_ms") or 9999) < 500)

    # m2: odd values through the real module
    clear()
    odd_host = "evil\"host'\nsecond line; $(id) `id` \\ %s end=1"
    r = pamlab(conf, user="ro\"ot", tty="/dev/pts/9", rhost=odd_host, ruser="al'ice")
    names = events()
    if eq(who, "m2 odd PAM values: the session opens and one event is written", (r.get("open"), len(names)), (0, 1)):
        f, data = fields(os.path.join(queue, names[0]))
        eq(who, "m2 quotes, a newline and shell words stay inside their field",
           (f.get("rhost"), f.get("user"), f.get("ruser")), (odd_host.encode(), b'ro"ot', b"al'ice"))
    clear()

    # m3: no hook file
    service(args.replace(REAL_HOOK, os.path.join(lab, "bin", "missing")))
    r = pamlab(conf)
    eq(who, "m3 the hook file is missing: the session still opens", (r.get("start"), r.get("open")), (0, 0))

    # m4: the hook fails
    bad = os.path.join(lab, "bin", "fail")
    write(bad, "#!/bin/sh\nexit 3\n", 0o755)
    service(args.replace(REAL_HOOK, bad))
    r = pamlab(conf)
    eq(who, "m4 the hook exits 3: the session still opens", (r.get("start"), r.get("open")), (0, 0))

    # m5: the hook hangs, ignores TERM, and has a child
    hang = os.path.join(lab, "bin", "hang")
    write(hang, "#!/bin/sh\ntrap '' TERM INT HUP\nsleep 31 &\necho $! > \"$0.child\"\necho $$ > \"$0.pid\"\nsleep 30\n", 0o755)
    service(args.replace(REAL_HOOK, hang))
    r = pamlab(conf)
    eq(who, "m5 the hook hangs: the session still opens", (r.get("start"), r.get("open")), (0, 0))
    ms = r.get("open_ms") or 0
    check(who, "m5 a hook that hangs holds a login up for about 1 s, never 2 (%d ms)" % ms, 900 <= ms < 2000)
    check(who, "m5 the hanging hook is gone afterwards", gone(hang + ".pid"))
    check(who, "m5 and so is the process it started", gone(hang + ".child"))

    # m6: why the limit is on the line: pam_exec itself waits without one
    hang2 = os.path.join(lab, "bin", "hang2")
    write(hang2, "#!/bin/sh\necho $$ > \"$0.pid\"\nexec sleep 30\n", 0o755)
    service("quiet seteuid type=open_session " + hang2)
    r = pamlab(conf, limit=3)
    check(who, "m6 without the time limit on the line, pam_exec waits for a hanging hook (still waiting after 3 s)",
          r.get("waiting") is True, r)
    gone(hang2 + ".pid", wait=0)

    # m7: the module file itself is missing
    write(os.path.join(conf, "nomod"), "session\trequired\t%s\nsession\t%s\t/nonexistent/pam_exec.so %s\n" % (permit, control, args))
    r = pamlab(conf, service="nomod")
    eq(who, "m7 pam_exec.so itself is missing: an optional line does not fail the session", (r.get("start"), r.get("open")), (0, 0))


# ---------------------------------------------------------- t: pam-auth-update
SYSTEMD_PROFILE = ("Name: Register user sessions in the systemd control group hierarchy\nDefault: yes\nPriority: 0\n"
                   "Session-Interactive-Only: yes\nSession-Type: Additional\nSession:\n\toptional\tpam_systemd.so\n")
CAP_PROFILE = ("Name: Inheritable Capabilities Management\nDefault: yes\nPriority: 0\nAuth-Type: Additional\n"
               "Auth:\n\toptional\t\t\tpam_cap.so\n")
OTHER_PROFILE = ("Name: A profile of another package\nDefault: yes\nPriority: 0\nSession-Type: Additional\n"
                 "Session:\n\toptional\tpam_other.so\n")
OLD_LINE = "\toptional\tpam_exec.so quiet " + REAL_HOOK
# The session lines of the services that run the hook, in the order the
# packages of all five releases have them (openssh-server, login,
# util-linux, sudo, cron; read from the unpacked .debs on 26 November
# 2026). Only what matters here: where pam_env stands, and what it reads.
STOCK_SERVICES = {
    "sshd": "@include common-auth\naccount    required     pam_nologin.so\n@include common-account\n"
            "session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close\n"
            "session    required     pam_loginuid.so\nsession    optional     pam_keyinit.so force revoke\n"
            "@include common-session\nsession    optional     pam_motd.so  motd=/run/motd.dynamic\n"
            "session    required     pam_limits.so\nsession    required     pam_env.so # [1]\n"
            "session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale\n@include common-password\n",
    "login": "auth       optional   pam_faildelay.so  delay=3000000\nsession    required     pam_loginuid.so\n"
             "session       required   pam_env.so readenv=1\nsession       required   pam_env.so readenv=1 envfile=/etc/default/locale\n"
             "@include common-auth\n@include common-account\n@include common-session\n@include common-password\n",
    "su": "auth       sufficient pam_rootok.so\nsession       required   pam_env.so readenv=1\n"
          "session       required   pam_env.so readenv=1 envfile=/etc/default/locale\nsession    optional   pam_mail.so nopen\n"
          "session    required   pam_limits.so\n@include common-auth\n@include common-account\n@include common-session\n",
    "su-l": "auth\t\tinclude\t\tsu\naccount\t\tinclude\t\tsu\npassword\tinclude\t\tsu\n"
            "session\t\toptional\tpam_keyinit.so force revoke\nsession\t\tinclude\t\tsu\n",
    "sudo-i": "#%PAM-1.0\nsession    required   pam_limits.so\nsession    required   pam_env.so readenv=1 user_readenv=0\n"
              "session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0\n"
              "@include common-auth\n@include common-account\n@include common-session\n",
    "sudo": "#%PAM-1.0\nsession    required   pam_limits.so\nsession    required   pam_env.so readenv=1 user_readenv=0\n"
            "@include common-auth\n@include common-account\n@include common-session-noninteractive\n",
    "cron": "@include common-auth\nsession       required   pam_env.so\n@include common-account\n"
            "@include common-session-noninteractive\nsession    required   pam_limits.so\n",
    "other": "@include common-auth\n@include common-account\n@include common-password\n@include common-session\n",
}
END_MARK = "# end of pam-auth-update config"
TREE_FILES = ["etc/pam.d/common-auth", "etc/pam.d/common-account", "etc/pam.d/common-password", "etc/pam.d/common-session",
              "etc/pam.d/common-session-noninteractive", "var/lib/pam/auth", "var/lib/pam/account", "var/lib/pam/password",
              "var/lib/pam/session", "var/lib/pam/session-noninteractive", "var/lib/pam/seen"]


def sha(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return "absent"


class Tree:
    """A lab root with its own copy of the release's pam-auth-update."""

    def __init__(self, xdir, work, name, label, src=None):
        self.set = name
        self.base = os.path.join(work, "t-" + name, label)
        self.root = os.path.join(self.base, "root")
        self.pkg = os.path.join(xdir, name, "libpam-runtime")
        if src is None:
            for d in ("etc/pam.d", "var/lib/pam", "usr/share/pam-configs"):
                os.makedirs(os.path.join(self.root, d))
        else:
            shutil.copytree(src.root, self.root, symlinks=True)
        script = read(os.path.join(self.pkg, "root", "usr", "sbin", "pam-auth-update"))
        self.reads_first = script.index("opendir(DIR, $inputdir)") < script.index("$opt eq '--root'")
        pairs = [("'/var/lib/dpkg/info/libpam-runtime.templates'", "'%s/control/templates'" % self.pkg),
                 ("'/usr/share/pam/common-'", "'%s/root/usr/share/pam/common-'" % self.pkg)]
        if self.reads_first:
            pairs.append(("my $inputdir = '/usr/share/pam-configs';", "my $inputdir = '%s/usr/share/pam-configs';" % self.root))
        for old, new in pairs:
            if old not in script:
                raise SystemExit("%s: cannot patch the lab copy of pam-auth-update (%s)" % (name, old))
            script = script.replace(old, new)
        self.tool = os.path.join(self.base, "pam-auth-update")
        write(self.tool, script, 0o755)
        # the debconf database that plays the host's own
        self.db = os.path.join(self.base, "hostdb")
        os.makedirs(self.db, exist_ok=True)
        self.dbconf = os.path.join(self.base, "hostdb.conf")
        write(self.dbconf, "Config: configdb\nTemplates: templatedb\n\nName: configdb\nDriver: File\nFilename: %s/config.dat\n\n"
                           "Name: templatedb\nDriver: File\nFilename: %s/templates.dat\n" % (self.db, self.db))

    def path(self, rel):
        return os.path.join(self.root, rel)

    def pau(self, *args):
        """The release's pam-auth-update, for real, on this tree."""
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive",
               "DEBCONF_SYSTEMRC": self.dbconf, "DEBCONF_NOWARNINGS": "yes", "HOME": "/nonexistent"}
        return subprocess.run([self.tool, "--root", self.root] + list(args), env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120, check=False)

    def helper(self, candidate=True, before=""):
        cmd = [sys.executable, "-I", HELPER, "--work", os.path.join(self.base, "work"), "--expect-line", LINE,
               "--sysroot", self.root, "--tool", self.tool]
        if candidate:
            cmd += ["--candidate", PROFILE]
        if before:
            cmd += ["--before", before]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        shutil.rmtree(os.path.join(self.base, "work"), ignore_errors=True)
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"error": (p.stdout + p.stderr)[-400:]}

    def snap(self):
        """Every file under the root: path -> sha256."""
        out = {}
        for d, _dirs, names in os.walk(self.root):
            for n in names:
                p = os.path.join(d, n)
                out[os.path.relpath(p, self.root)] = sha(p)
        return out

    def files(self):
        return {"/" + rel: sha(self.path(rel)) for rel in TREE_FILES}

    def session(self):
        return read(self.path("etc/pam.d/common-session")).split("\n")


def pam_update_checks(xdir, work, name):
    who = name
    t = Tree(xdir, work, name, "pristine")
    blind = t.reads_first
    info(who, "pam-auth-update reads the profiles %s its --root option" % ("BEFORE" if blind else "after"))
    shutil.copy(os.path.join(t.pkg, "root", "usr", "share", "pam-configs", "unix"), t.path("usr/share/pam-configs/unix"))
    write(t.path("usr/share/pam-configs/systemd"), SYSTEMD_PROFILE)
    write(t.path("usr/share/pam-configs/capability"), CAP_PROFILE)
    p = t.pau("--package", "--force")
    sess = t.session() if os.path.exists(t.path("etc/pam.d/common-session")) else []
    if not check(who, "t0 the release's own pam-auth-update builds the lab tree (pam_unix and pam_systemd in common-session)",
                 p.returncode == 0 and any("pam_unix.so" in x for x in sess)
                 and any(x.startswith("session\toptional\tpam_systemd.so") for x in sess)
                 and sorted(read(t.path("var/lib/pam/seen")).split()) == ["capability", "systemd", "unix"],
                 (p.returncode, p.stderr[-300:], sess[-6:])):
        return
    before_all = t.snap()

    # t1: a pristine tree
    o1 = t.helper()
    if "error" in o1:
        check(who, "t1 the trial helper answers", False, o1["error"])
        return
    eq(who, "t1 pristine: usable, not refused, nothing of others waiting, no profile, no hook line",
       (o1["usable"], o1["refused"], o1["pending"], o1["profile"], o1["enabled"], o1["hook_lines"], o1["problems"]),
       (True, False, [], "absent", False, [], []))
    eq(who, "t1 the helper knows whether this pam-auth-update reads the copy's profiles", o1["reads_copy"], not blind)
    three = ["/etc/pam.d/common-session", "/var/lib/pam/seen", "/var/lib/pam/session"]
    if blind:
        eq(who, "t1 a profile that is only in the copy cannot be tried here: the helper says so (blind), and does not say ok",
           (o1["enable"]["blind"], o1["enable"]["ok"]), (True, False))
    else:
        eq(who, "t1 the trial adds exactly auto_sec's one line", (o1["enable"]["ok"], o1["enable"]["blind"],
                                                                  o1["enable"]["session_added"], o1["enable"]["session_removed"]),
           (True, False, [SHOWN], []))
        eq(who, "t1 the trial changes common-session and pam-auth-update's two records, nothing else",
           (o1["enable"]["changed"], o1["enable"]["unexpected"]), (three, []))
    eq(who, "t1 a removal has nothing to do here", (o1["remove"]["ok"], o1["remove"]["noop"], o1["remove"]["as_before"]),
       (True, True, "unknown"))

    # t2: a hand edit inside pam-auth-update's block
    e = Tree(xdir, work, name, "edit-inside", t)
    text = read(e.path("etc/pam.d/common-session"))
    write(e.path("etc/pam.d/common-session"), text.replace(END_MARK, "session optional pam_lastlog.so\n" + END_MARK, 1))
    o = e.helper()
    eq(who, "t2 a line added by hand inside pam-auth-update's block: refused (R08-P1)", o.get("refused"), True)
    check(who, "t2 and the trial of the profile is not called ok", not o.get("enable", {}).get("ok", False))

    # t3: a hand edit outside the blocks
    e = Tree(xdir, work, name, "edit-outside", t)
    with open(e.path("etc/pam.d/common-session"), "a", encoding="utf-8") as fh:
        fh.write("session optional pam_lastlog.so\n")
    o = e.helper()
    eq(who, "t3 a line added by hand after the blocks is fine for pam-auth-update: not refused, nothing waiting",
       (o.get("refused"), o.get("pending")), (False, []))
    if not blind:
        eq(who, "t3 and the trial still adds exactly the one line", (o["enable"]["ok"], o["enable"]["session_added"],
                                                                     o["enable"]["session_removed"]), (True, [SHOWN], []))

    # t4: a profile of another package waits
    e = Tree(xdir, work, name, "waiting", t)
    write(e.path("usr/share/pam-configs/other"), OTHER_PROFILE)
    o = e.helper()
    check(who, "t4 a new profile of another package is not applied yet: the helper lists what would change with it (R08-P2)",
          o.get("refused") is False and "/etc/pam.d/common-session" in o.get("pending", []), o.get("pending"))

    # t5: an option added by hand to a line pam-auth-update wrote
    e = Tree(xdir, work, name, "option", t)
    text = read(e.path("etc/pam.d/common-session"))
    write(e.path("etc/pam.d/common-session"), re.sub(r"(?m)^(session\toptional\tpam_systemd\.so).*$", r"\1 debug", text, count=1))
    check(who, "t5 (the lab edit is in place)", "pam_systemd.so debug\n" in read(e.path("etc/pam.d/common-session")))
    o = e.helper()
    eq(who, "t5 an option added by hand to a managed line: pam-auth-update keeps it, not refused, nothing waiting",
       (o.get("refused"), o.get("pending")), (False, []))
    if not blind:
        eq(who, "t5 and the trial adds exactly the one line and takes none away",
           (o["enable"]["ok"], o["enable"]["session_added"], o["enable"]["session_removed"]), (True, [SHOWN], []))

    # t6: a line that names the hook, written by someone else
    e = Tree(xdir, work, name, "foreign-line", t)
    with open(e.path("etc/pam.d/common-session"), "a", encoding="utf-8") as fh:
        fh.write("session optional pam_exec.so " + REAL_HOOK + "\n")
    o = e.helper()
    eq(who, "t6 a hook line auto_sec did not write is reported (R08-P5)",
       o.get("hook_lines_other"), [["common-session", "session optional pam_exec.so " + REAL_HOOK]])
    e = Tree(xdir, work, name, "pasted-line", t)
    with open(e.path("etc/pam.d/common-session"), "a", encoding="utf-8") as fh:
        fh.write(LINE + "\n")
    o = e.helper()
    eq(who, "t6 also auto_sec's exact line, pasted by hand outside pam-auth-update's block", len(o.get("hook_lines_other", [])), 1)

    # t6b: PAM's environment reaches the hook, which runs as root (R08-P6)
    e = Tree(xdir, work, name, "pam-env", t)
    for svc, text in STOCK_SERVICES.items():
        write(e.path("etc/pam.d/" + svc), text)
    o = e.helper()
    eq(who, "t6b the service files as Debian and Ubuntu ship them (sshd reads ~/.pam_environment AFTER the common session lines): fine",
       o.get("user_env_early"), [])
    write(e.path("etc/pam.d/early-session"), "session required pam_env.so user_readenv=1\n@include common-session\n")
    write(e.path("etc/pam.d/early-auth"), "auth\trequired\tpam_env.so readenv=1 user_readenv=1\n@include common-auth\n@include common-session\n")
    write(e.path("etc/pam.d/early-nested"), "session [success=ok default=bad] pam_env.so user_readenv=1\nsession include su\n")
    write(e.path("etc/pam.d/no-hook"), "session required pam_env.so user_readenv=1\n@include common-session-noninteractive\n")
    write(e.path("etc/pam.d/comment"), "# session required pam_env.so user_readenv=1\n@include common-session\n"
                                         "session required pam_env.so user_readenv=0\n")
    o = e.helper()
    eq(who, "t6b a service that reads a user's own environment file before the common session lines is reported (R08-P6), "
            "also through an include or in its auth lines; not one that never runs the hook, not a comment",
       o.get("user_env_early"), [["early-auth", "auth"], ["early-nested", "session"], ["early-session", "session"]])

    # t6c: a pam-auth-update without a --root option. pam-auth-update's
    # option loop has no branch for an option it does not know (read in all
    # five pinned releases): it ignores it. A tool without --root would take
    # the trial's "--root <copy> --package" as plain "--package" and run on
    # the real files. The helper must never start it.
    e = Tree(xdir, work, name, "no-root-option", t)
    mark = os.path.join(e.base, "tool-was-started")
    write(e.tool, "#!/bin/sh\n# stands for a pam-auth-update from before that option\necho started >> '%s'\nexit 0\n" % mark, 0o755)
    before = e.snap()
    o = e.helper()
    eq(who, "t6c a pam-auth-update without a --root option: not usable, and the helper says why (R08-P3)",
       (o.get("usable"), o.get("root_option"), o.get("problems")),
       (False, False, ["this pam-auth-update has no --root option, so the change cannot be tried on a copy first "
                       "(it would run on the real PAM files)"]))
    check(who, "t6c ... and the helper never started it", not os.path.exists(mark))
    eq(who, "t6c ... and nothing in that tree changed", e.snap(), before)
    eq(who, "t6c (the release's own pam-auth-update has the option, and the trial left the real files alone)",
       (o1["root_option"], o1["host_changed"]), (True, []))

    # t6d: a pam-auth-update that writes the real files during a trial
    # (it names the option, and does not keep to it). The helper compares
    # the real files before and after, and says which changed (R08-P7).
    e = Tree(xdir, work, name, "writes-outside", t)
    write(e.tool, "#!/bin/sh\n# names '--root' and ignores it\necho '# written behind the trial' >> '%s'\nexit 0\n"
          % e.path("etc/pam.d/common-session"), 0o755)
    o = e.helper()
    eq(who, "t6d a pam-auth-update that writes outside the copy: the helper lists the real files that changed (R08-P7)",
       o.get("host_changed"), ["/etc/pam.d/common-session"])

    # t7: read-only
    eq(who, "t7 the helper wrote nothing in the tree it looked at", t.snap(), before_all)

    # t8: the profile in place, not enabled yet (what pam.yml does at P4)
    shutil.copy(PROFILE, t.path("usr/share/pam-configs/" + NAME))
    with_profile = t.snap()
    o8 = t.helper()
    eq(who, "t8 with the profile file in place: it is auto_sec's, nothing of others waits, the trial is ok and not blind",
       (o8["profile"], o8["pending"], o8["enable"]["ok"], o8["enable"]["blind"], o8["enable"]["session_added"],
        o8["enable"]["session_removed"], o8["enable"]["changed"]), ("ours", [], True, False, [SHOWN], [], three))
    if not blind:
        eq(who, "t8 the trial gives the same files as the trial the plan was made from (M08-2)",
           o8["enable"]["after"], o1["enable"]["after"])
    eq(who, "t8 the helper wrote nothing", t.snap(), with_profile)
    write(os.path.join(t.base, "pam-before.json"), json.dumps({k: v for k, v in o1["now"].items() if "pam-configs" not in k}))

    # t9: enable for real
    p = t.pau("--package", "--enable", NAME)
    eq(who, "t9 pam-auth-update --package --enable, for real: rc 0", p.returncode, 0)
    eq(who, "t9 the real run gave exactly the files the trial showed (M08-3)", t.files(), o8["enable"]["after"])
    sess = t.session()
    eq(who, "t9 common-session holds auto_sec's line once", sess.count(LINE), 1)
    eq(who, "t9 no other common file holds it (cron, plain sudo and services read common-session-noninteractive)",
       [n for n in ("common-auth", "common-account", "common-password", "common-session-noninteractive")
        if "auto-sec-login-hook" in read(t.path("etc/pam.d/" + n))], [])
    o10 = t.helper(before=os.path.join(t.base, "pam-before.json"))
    eq(who, "t10 installed: the helper sees the line in pam-auth-update's block, and a second run would change nothing",
       (o10["enabled"], o10["enabled_in_block"], o10["hook_lines_other"], o10["enable"]["noop"], o10["enable"]["ok"], o10["pending"]),
       (True, True, [], True, True, []))
    eq(who, "t10 the trial of the removal takes out exactly that line, and the files are then as before the install",
       (o10["remove"]["ok"], o10["remove"]["noop"], o10["remove"]["session_removed"], o10["remove"]["session_added"],
        o10["remove"]["as_before"], o10["remove"]["differs"]), (True, False, [SHOWN], [], "yes", []))

    # t11: installed, then a hand edit inside the block
    e = Tree(xdir, work, name, "installed-edit", t)
    text = read(e.path("etc/pam.d/common-session"))
    write(e.path("etc/pam.d/common-session"), text.replace(END_MARK, "session optional pam_lastlog.so\n" + END_MARK, 1))
    o = e.helper(candidate=False)
    eq(who, "t11 installed, then hand edits inside the block: the removal is refused too (R08-P1), not forced",
       (o.get("refused"), o.get("remove", {}).get("ok")), (True, False))

    # t12: remove for real
    installed = t.snap()
    p = t.pau("--package", "--remove", NAME)
    eq(who, "t12 pam-auth-update --package --remove, for real: rc 0", p.returncode, 0)
    eq(who, "t12 the real removal gave exactly the files the trial showed (M08-3)", t.files(), o10["remove"]["after"])
    os.remove(t.path("usr/share/pam-configs/" + NAME))
    after = t.snap()
    eq(who, "t12 after the removal every file is byte for byte what it was before the install",
       (after == before_all, sorted(k for k in set(after) | set(before_all) if after.get(k) != before_all.get(k))), (True, []))
    check(who, "t12 (the install had changed %d files)" % len([k for k in installed if installed[k] != before_all.get(k)]),
          installed != before_all)

    # t13: an older profile of auto_sec's own is installed; this release's profile replaces it
    header = read(PROFILE).split("\n")[0]
    old_profile = "\n".join([header] + [ln for ln in read(PROFILE).split("\n")[1:] if not ln.startswith("\t") and ln] + [OLD_LINE]) + "\n"
    u = Tree(xdir, work, name, "older", t)
    write(u.path("usr/share/pam-configs/" + NAME), old_profile)
    p = u.pau("--package", "--enable", NAME)
    old_full = "session" + OLD_LINE
    if not eq(who, "t13 an older auto_sec profile with another line is installed in a lab tree", (p.returncode, u.session().count(old_full)), (0, 1)):
        return
    o = u.helper()
    eq(who, "t13 the older line is auto_sec's own (its profile carries the header): not reported as foreign",
       (o["profile"], o["hook_lines_other"], o["pending"]), ("ours", [], []))
    if blind:
        eq(who, "t13 the new profile cannot be tried on a copy here: blind, not ok", (o["enable"]["blind"], o["enable"]["ok"]), (True, False))
    else:
        eq(who, "t13 the trial: the new line comes, the older one goes, nothing else",
           (o["enable"]["ok"], o["enable"]["session_added"], o["enable"]["session_removed"]), (True, [SHOWN], [OLD_SHOWN]))
    shutil.copy(PROFILE, u.path("usr/share/pam-configs/" + NAME))
    o2 = u.helper()
    eq(who, "t13 with the new profile in place the trial is ok on every release",
       (o2["enable"]["ok"], o2["enable"]["blind"], o2["enable"]["session_added"], o2["enable"]["session_removed"]),
       (True, False, [SHOWN], [OLD_SHOWN]))
    p = u.pau("--package", "--enable", NAME)
    eq(who, "t13 the real run gives exactly those files", (p.returncode, u.files()), (0, o2["enable"]["after"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--x", required=True)
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    os.makedirs(a.work, exist_ok=True)
    static_checks()
    sets = sorted(os.listdir(a.x))
    for name in sets:
        if os.path.isdir(os.path.join(a.x, name, "libpam-modules")):
            pam_exec_checks(a.x, a.work, name)
    for name in sets:
        if os.path.isdir(os.path.join(a.x, name, "libpam-runtime")):
            pam_update_checks(a.x, a.work, name)
    print("test_pam: %d passed, %d failed" % (COUNT["pass"], COUNT["fail"]))
    return 1 if COUNT["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
