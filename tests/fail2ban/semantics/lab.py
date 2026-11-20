#!/usr/bin/env python3
"""fail2ban-semantics lab for role 03 (issue #2). run.sh calls it; see there.

Runs role 03's own trial helper (roles/03-firewall/files/auto-sec-f2b-check)
against unpacked fail2ban builds, as this user, and checks how fail2ban
reads auto_sec's 00-autosec.conf next to the operator's files:

  S1  read order (fail2ban's own -vvv trace)
  S2  the canary's layout: no effective change, byte-identical -d dump
  S3  a stock layout: exactly auto_sec's keys change
  S4  migration of an auto_sec 0.1-0.4 jail.local
  S5  which jail.local counts as auto_sec 0.1-0.4's
  S6  leaks into jails of the operator
  S7  addresses auto_sec wants ignored (CIDR-aware)
  S8  the sshd jail's port vs ssh_port
  S9  files read BEFORE auto_sec's that set the same value (R5)
  S10 a broken live config
  S11 why auto_sec never writes %(known/...)s
  S12 the rendered templates
  S14 the helper: Python 3.10 syntax, -I, braces never leave it
The slow-scanner files (fail2ban_slow_scanners: jail.d/00-autosec-slow.conf
and fail2ban.d/00-autosec.conf), all builds:
  S17 the jails sshd-slow and recidive next to the operator's files: nothing
      else changes; log source, ban action and ignore list of the sshd jail
  S18 when recidive is left out (yours, log target, ban action, sub-switch)
  S19 dbpurgeage: the operator's minimum, what the jails need, what the
      server has; never shortened
  S20 what the role refuses: a foreign [sshd-slow], an ignoreip read before
  S21 fail2ban's own code, run without a server: what a purge deletes, how
      ban times grow
With --server-python (a Python that imports asyncore; the noble build only):
  S13 reload/restart semantics of a real fail2ban 1.0.2 server
  S15 the helper's drift check and --verify against that server
  S16 role 03's own task files (preflight, trial, decide, apply, report)
      run by ansible-playbook against that server (--ansible, repeatable)
  S22 the slow-scanner jails on real servers (noble 1.0.2 and resolute
      1.1.0): a slow scanner, a person's typos, recidive, growing and
      permanent bans, purge and restart
  S23 role 03's slow-scanner task files run by ansible-playbook (--ansible)

The checks of one build, the S16 runs of each ansible-playbook, and the S23
cases, run side by side (--jobs); each group's lines are printed together,
in a fixed order.

Exit 0 = every check passed, 1 = a check failed, 2 = setup problem.
"""
import argparse
import ast
import glob
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import traceback

FAILS = []
PASSES = [0]
LOCK = threading.RLock()
LOCAL = threading.local()
OWN = "00-autosec.conf"
NGINX = "00-autosec-nginx.conf"
SLOW = "00-autosec-slow.conf"
SLOW_REL = "jail.d/" + SLOW
DB_REL = "fail2ban.d/00-autosec.conf"
# The only "%" auto_sec writes: fail2ban's own references in the slow file.
SLOW_REFS = ("%(sshd/backend)s", "%(sshd/logpath)s", "%(sshd/banaction)s", "%(sshd/ignoreip)s",
             "%(banaction_allports)s", "%(known/ignoreip)s")
REC_LOG = "[recidive]\nlogpath = @LOGS@/fail2ban.log\n"
F2B_LOG = "[Definition]\nlogtarget = @LOGS@/fail2ban.log\n"
IPS = ("203.0.113.7", "198.51.100.9", "2001:db8::/32")
MARKER = "# Written by auto_sec (role 03). Do not edit: the next run replaces this file."
CLIENT_CODE = ("import sys; sys.path.insert(0, sys.argv[1]); "
               "from fail2ban.client.fail2banclient import exec_command_line; "
               "exec_command_line(['fail2ban-client'] + sys.argv[2:])")
SERVER_CODE = ("import sys; sys.path.insert(0, sys.argv[1]); "
               "from fail2ban.client.fail2banserver import exec_command_line; "
               "exec_command_line(['fail2ban-server'] + sys.argv[2:])")


def emit(line):
    buf = getattr(LOCAL, "buf", None)
    if buf is None:
        print(line, flush=True)
    else:
        buf.append(line)


def ok(tag, what):
    with LOCK:
        PASSES[0] += 1
    emit("PASS  %-9s %s" % (tag, what))


def bad(tag, what):
    with LOCK:
        FAILS.append("%s %s" % (tag, what))
    emit("FAIL  %-9s %s" % (tag, what))


def in_parallel(jobs, units):
    """units: [(tag, function)]. Runs them in up to `jobs` threads (each one
    mostly waits for its own child processes). The lines of a unit are
    printed together, in the order of `units`; a unit that raises is a FAIL."""
    def work(i, gate, bufs):
        with gate:
            LOCAL.buf = bufs[i]
            try:
                units[i][1]()
            except Exception:
                bad(units[i][0], "check crashed: " + traceback.format_exc()[-1500:])
    if jobs <= 1 or len(units) <= 1:
        for tag, fn in units:
            try:
                fn()
            except Exception:
                bad(tag, "check crashed: " + traceback.format_exc()[-1500:])
        return
    gate, bufs = threading.Semaphore(jobs), [[] for _ in units]
    threads = [threading.Thread(target=work, args=(i, gate, bufs)) for i in range(len(units))]
    for th in threads:
        th.start()
    for i, th in enumerate(threads):
        th.join()
        for line in bufs[i]:
            print(line, flush=True)


def expect(tag, what, got, want):
    if got == want:
        ok(tag, "%s: %s" % (what, short(got)))
    else:
        bad(tag, "%s: got %s, want %s" % (what, short(got), short(want)))


def check(tag, what, cond, detail=""):
    if cond:
        ok(tag, what)
    else:
        bad(tag, "%s %s" % (what, short(detail)))


def short(v, n=300):
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
    return s if len(s) <= n else s[:n] + "..."


def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(2)


def run(argv, timeout=300, env=None, cwd="/"):
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                       env=env, cwd=cwd, check=False)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def write(path, content, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.lexists(path):
        os.unlink(path)
    with open(path, "wb") as f:
        f.write(content.encode() if isinstance(content, str) else content)
    if mode is not None:
        os.chmod(path, mode)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class Lab:
    def __init__(self, a):
        self.a = a
        self.w = os.path.abspath(a.work)
        self.logs = os.path.join(self.w, "logs")
        for p in ("nginx/error.log", "nginx/access.log", "fail2ban.log", "auth.log"):
            write(os.path.join(self.logs, p), "")
        self.cand = {os.path.splitext(os.path.basename(p))[0]: p
                     for p in glob.glob(os.path.join(a.rendered, "*.conf"))}
        os.makedirs(os.path.join(self.w, "bin"), exist_ok=True)
        self.n = 0

    # --- builds --------------------------------------------------------------
    def x(self, dist):
        return os.path.join(self.w, "x", dist)

    def pypath(self, dist):
        return os.path.join(self.x(dist), "usr/lib/python3/dist-packages")

    def client(self, dist):
        """Wrapper script; its path is the helper's --client (no spaces)."""
        p = os.path.join(self.w, "bin", "f2bc-" + dist)
        with LOCK:
            if not os.path.exists(p):
                write(p, "#!/bin/sh\ncd / || exit 2\nexec %s -I -B -c \"%s\" %s \"$@\"\n"
                      % (sys.executable, CLIENT_CODE, self.pypath(dist)), 0o755)
        return p

    def conffiles(self, dist):
        """dpkg-query -f '${Conffiles}' format, md5 of the unpacked files."""
        p = os.path.join(self.w, "conffiles-" + dist)
        with LOCK:
            if not os.path.exists(p):
                lst = os.path.join(self.w, "ctrl", dist, "conffiles")
                out = []
                for ln in read(lst).split():
                    f = os.path.join(self.x(dist), ln.lstrip("/"))
                    if os.path.isfile(f):
                        out.append(" %s %s" % (ln, hashlib.md5(open(f, "rb").read()).hexdigest()))
                write(p, "\n".join(out) + "\n")
        return p

    def tree(self, dist, files=None, name=None):
        """Stock /etc/fail2ban of <dist> plus files {rel: content | None}.
        paths-overrides.local points sshd/nginx log paths at empty lab files
        (it sets no key auto_sec sets)."""
        with LOCK:
            self.n += 1
            d = os.path.join(self.w, "t", "%s-%03d-%s" % (dist, self.n, name or "case"))
        shutil.rmtree(d, ignore_errors=True)
        shutil.copytree(os.path.join(self.x(dist), "etc/fail2ban"), d, symlinks=True)
        write(os.path.join(d, "paths-overrides.local"),
              "[DEFAULT]\nsshd_log = %s/auth.log\nnginx_error_log = %s/nginx/error.log\n"
              "nginx_access_log = %s/nginx/access.log\n" % (self.logs, self.logs, self.logs))
        for rel, content in (files or {}).items():
            p = os.path.join(d, rel)
            if content is None:
                if os.path.lexists(p):
                    os.unlink(p)
            else:
                write(p, content.replace("@LOGS@", self.logs))
        return d

    def helper(self, dist, tree, cand="default", name=OWN, ssh_port=22, jails=("sshd",),
               ips=(), keys=("bantime", "bantime.increment", "bantime.factor", "findtime", "maxretry"),
               running=False, conf_for_running=None, own=()):
        work = tree + ".work"
        shutil.rmtree(work, ignore_errors=True)
        cpath = self.cand.get(cand, cand)
        argv = [sys.executable, "-I", self.a.helper, "--conf", tree, "--work", work,
                "--candidate", cpath, "--candidate-name", name, "--ssh-port", str(ssh_port),
                "--client", self.client(dist), "--conffiles", self.conffiles(dist)]
        argv += ["--allowed-jail=" + j for j in jails] + ["--autosec-ip=" + i for i in ips]
        argv += ["--autosec-key=" + k for k in keys] + ["--own-file=" + f for f in own]
        if running:
            argv += ["--running", "--runtime-ignore-file", os.path.join(self.w, "no-such-file")]
        rc, out, err = run(argv)
        if rc != 0:
            bad(dist, "helper rc %s: %s" % (rc, err.strip()[-400:]))
            return {}
        return json.loads(out)

    def helper_slow(self, dist, tree, cand="slow", alt="slow-norec", db="slow-db", db_min="30d", ips=(),
                    controller="", running=False):
        """The trial of the slow-scanner files, as tasks/slow-trial.yml runs it:
        the jail file with recidive (cand) and without (alt; None when the
        sub-switch is off and cand has none), and the fail2ban.d file."""
        work = tree + ".work"
        shutil.rmtree(work, ignore_errors=True)
        argv = [sys.executable, "-I", self.a.helper, "--conf", tree, "--work", work,
                "--candidate", self.cand.get(cand, cand), "--candidate-name", SLOW,
                "--db-candidate", self.cand.get(db, db), "--db-min", db_min, "--ssh-port", "22",
                "--controller-ip", controller, "--client", self.client(dist), "--conffiles", self.conffiles(dist)]
        if alt:
            argv += ["--candidate-alt", self.cand.get(alt, alt)]
        argv += ["--autosec-ip=" + i for i in ips]
        if running:
            argv += ["--running", "--runtime-ignore-file", os.path.join(self.w, "no-such-file")]
        rc, out, err = run(argv)
        if rc != 0:
            bad(dist, "slow helper rc %s: %s" % (rc, err.strip()[-400:]))
            return {}
        return json.loads(out)

    def dump(self, dist, conf, *extra):
        return run([self.client(dist), "-c", conf] + list(extra) + ["-d"])

    def trace(self, dist, conf):
        rc, out, err = run([self.client(dist), "-c", conf, "-vvv", "-d"])
        files, in_jail = [], False
        for ln in err.splitlines():
            if "Reading configs for jail under " in ln:
                in_jail = True
                continue
            if in_jail and re.search(r"(Reading|Loading) configs for ", ln):
                break
            m = re.search(r"Reading file: (.+?)\s*$", ln) if in_jail else None
            if m and os.path.isfile(m.group(1)):
                files.append(os.path.relpath(m.group(1), conf))
        return files


def keyset(changes, jail=None):
    return sorted({("action" if c["key"].startswith("action ") else c["key"])
                   for c in changes if jail is None or c["jail"] == jail})


def jailset(changes):
    return sorted({c["jail"] for c in changes})


def strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)


# --- S1-S12, S14: config reader, all builds ------------------------------------

def canary_of(lab, d):
    """The canary's jail.local for this build, and its jails."""
    canary = read(os.path.join(lab.a.fixtures, "canary.jail.local")).replace("/var/log/", "@LOGS@/")
    canary_jails = ["sshd", "nginx-http-auth", "nginx-botsearch", "nginx-bad-request", "recidive"]
    if not os.path.exists(os.path.join(lab.x(d), "etc/fail2ban/filter.d/nginx-bad-request.conf")):
        # fail2ban 0.11 (jammy) has no nginx-bad-request filter (added in 1.0).
        canary = re.sub(r"(?ms)^\[nginx-bad-request\]$.*?(?=^\[)", "", canary)
        canary_jails.remove("nginx-bad-request")
    return canary, canary_jails


def config_checks(lab, d):
    canary, canary_jails = canary_of(lab, d)
    legacy3 = read(os.path.join(lab.a.fixtures, "legacy-0.3.jail.local"))
    legacy4 = read(os.path.join(lab.a.fixtures, "legacy-0.4.jail.local"))
    early_names = ["0-zero.conf", "Zcap.conf", "_under.conf", "aaa.conf"]

    # S1 read order
    files = {"jail.d/" + n: "[DEFAULT]\n" for n in early_names}
    files.update({"jail.d/" + OWN: read(lab.cand["default"]), "jail.d/" + NGINX: read(lab.cand["nginx"]),
                  "jail.local": "[DEFAULT]\n", "jail.d/zz-tail.local": "[DEFAULT]\n"})
    t = lab.tree(d, files, "order")
    got = lab.trace(d, t)
    want = ["jail.conf", "paths-debian.conf", "paths-common.conf", "paths-overrides.local",
            "jail.d/0-zero.conf", "jail.d/" + NGINX, "jail.d/" + OWN, "jail.d/Zcap.conf",
            "jail.d/_under.conf", "jail.d/aaa.conf", "jail.d/defaults-debian.conf", "jail.local",
            "jail.d/zz-tail.local"]
    expect(d, "S1 read order", got, want)

    # S2 canary
    t = lab.tree(d, {"jail.local": canary}, "canary")
    r = lab.helper(d, t)
    expect(d, "S2 canary: live and new load", (r["live"]["ok"], r["live_test"]["ok"], r["new"]["ok"],
                                               r["new_test"]["ok"]), (True, True, True, True))
    expect(d, "S2 canary: changes", r["changes"], [])
    expect(d, "S2 canary: leaks", r["leaks"], [])
    expect(d, "S2 canary: read-before overrides", r["read_before_overrides"], [])
    expect(d, "S2 canary: jails", r["new"]["jails"], canary_jails)
    expect(d, "S2 canary: legacy type", r["legacy_jail_local"], "other")
    v = r["sshd"]["effective"]
    expect(d, "S2 canary: sshd values", (v["maxretry"], v["findtime"], v["bantime"], v["bantime.factor"],
                                         v["bantime.maxtime"]), ("3", "10m", "1h", "1", "8w"))
    expect(d, "S2 canary: port_ok / restart", (r["sshd"]["port_ok"], r["sshd_action_restart_needed"]),
           (True, False))
    rc1, live, _ = lab.dump(d, t + ".work/live")
    rc2, new, _ = lab.dump(d, t + ".work/new")
    expect(d, "S2 canary: raw -d dump live == new",
           (rc1, rc2, live.replace(t + ".work/live", "T") == new.replace(t + ".work/new", "T")), (0, 0, True))
    r = lab.helper(d, t, cand="ips", ips=("203.0.113.7", "198.51.100.9", "2001:db8::/32"))
    expect(d, "S2 canary + office IP: changes", r["changes"], [])
    expect(d, "S2 canary + office IP: W1 ignore_missing", r["ignore_missing"],
           ["203.0.113.7", "198.51.100.9", "2001:db8::/32"])
    check(d, "S2 canary + office IP: set_in names jail.local [DEFAULT]",
          r["sshd"]["set_in"].get("ignoreip", "").startswith("jail.local [DEFAULT]"), r["sshd"]["set_in"])

    # S3 stock layout
    t = lab.tree(d, {}, "stock")
    r = lab.helper(d, t)
    expect(d, "S3 stock: only the sshd jail changes", jailset(r["changes"]), ["sshd"])
    expect(d, "S3 stock: keys", keyset(r["changes"]),
           ["action", "bantime", "bantime.factor", "bantime.increment", "maxmatches", "maxretry"])
    expect(d, "S3 stock: port ssh -> 22 needs no jail restart", r["sshd_action_restart_needed"], False)
    expect(d, "S3 stock: leaks", r["leaks"], [])
    r = lab.helper(d, t, cand="empty", keys=())
    expect(d, "S3 stock, fail2ban_defaults {}: keys", keyset(r["changes"]), ["action"])
    r = lab.helper(d, t, cand="port2222", ssh_port=2222)
    expect(d, "S3 stock, ssh_port 2222: jail restart needed", r["sshd_action_restart_needed"], True)
    expect(d, "S3 stock, ssh_port 2222: port_ok", r["sshd"]["port_ok"], True)

    # S4 migration (the legacy files were rendered for ssh_port 2222)
    journal_before = d in ("jammy", "bookworm")
    for fix, cand, label in ((legacy3, "port2222", "0.3"), (legacy4, "legacy04", "0.4")):
        t = lab.tree(d, {"jail.local": fix}, "legacy" + label)
        ips = ("203.0.113.7", "198.51.100.0/24", "2001:db8::1") if label == "0.4" else ()
        r = lab.helper(d, t, cand=cand, ssh_port=2222, ips=ips)
        expect(d, "S4 %s: legacy type and migrate" % label, (r["legacy_jail_local"], r["migrate"]),
               ("a" if label == "0.3" else "b", True))
        nginx = sorted((c["jail"], c["key"], c["after"]) for c in r["changes"] if c["jail"] != "sshd")
        expect(d, "S4 %s: nginx jails go (they never worked)" % label, nginx,
               [("nginx-botsearch", "(jail)", "absent"), ("nginx-http-auth", "(jail)", "absent")])
        sshd = {c["key"]: (c["before"], c["after"]) for c in r["changes"] if c["jail"] == "sshd"}
        if journal_before:
            expect(d, "S4 %s: sshd leaves the journal" % label, sshd.get("backend"), ("systemd", "auto"))
            check(d, "S4 %s: no sshd ban value changes" % label,
                  not set(sshd) & {"maxretry", "findtime", "bantime", "bantime.increment", "bantime.factor",
                                   "addignoreip"}, sshd)
        else:
            expect(d, "S4 %s: sshd unchanged" % label, sshd, {})
        expect(d, "S4 %s: the migration drops no ignored address" % label, r["ignore_dropped"], [])
        if label == "0.3" and journal_before:
            r = lab.helper(d, t, cand="backend", ssh_port=2222, keys=("backend", "maxretry"))
            expect(d, "S4 0.3 + backend: systemd: only the nginx jails change", jailset(r["changes"]),
                   ["nginx-botsearch", "nginx-http-auth"])
    # A 0.3 file plus an ignoreip line the operator added has 0.4's shape
    # (type b). Migrating it with auto_sec's variables empty would drop the
    # operator's addresses (not the loopback ones): ignore_dropped names them,
    # and role 03 refuses (R4b).
    own_ign = legacy3.replace("[DEFAULT]\n", "[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 203.0.113.50 198.51.100.0/24\n", 1)
    t = lab.tree(d, {"jail.local": own_ign}, "legacy-ownign")
    r = lab.helper(d, t, cand="port2222", ssh_port=2222)
    expect(d, "S4 0.3 + your ignoreip line: type b, migrate", (r["legacy_jail_local"], r["migrate"]), ("b", True))
    expect(d, "S4 0.3 + your ignoreip line: addresses the migration would drop", r["ignore_dropped"],
           [{"addresses": ["203.0.113.50", "198.51.100.0/24"], "jail": "sshd"}])
    r = lab.helper(d, t, cand="legacy04", ssh_port=2222, ips=("203.0.113.7", "198.51.100.0/24", "2001:db8::1"))
    expect(d, "S4 ... covered by fail2ban_ignore_ips (a /24 covers it): only 203.0.113.50 is dropped",
           r["ignore_dropped"], [{"addresses": ["203.0.113.50"], "jail": "sshd"}])

    # S5 which jail.local is auto_sec 0.1-0.4's
    kinds = {
        "0.3": (legacy3, "a"), "0.4": (legacy4, "b"),
        "0.3 port 22": (legacy3.replace("port = 2222", "port = 22"), "a"),
        "0.3 no final newline": (legacy3.rstrip("\n"), "a"),
        "0.3 + comment": (legacy3 + "# mine now\n", "other"),
        "0.3 CRLF": (legacy3.replace("\n", "\r\n"), "other"),
        "0.4 + own IP text": (legacy4.replace("::1 ", "::1 example.org "), "other"),
        "canary": (canary, "other"),
    }
    for label, (content, want) in kinds.items():
        t = lab.tree(d, {"jail.local": content}, "kind")
        r = lab.helper(d, t, cand="port2222", ssh_port=2222)
        expect(d, "S5 legacy type of %s" % label, r.get("legacy_jail_local"), want)
    t = lab.tree(d, {"jail.local.real": legacy3}, "kindlink")
    os.symlink("jail.local.real", os.path.join(t, "jail.local"))
    r = lab.helper(d, t, cand="port2222", ssh_port=2222)
    expect(d, "S5 legacy type of a symlink to the 0.3 file", r.get("legacy_jail_local"), "other")
    t = lab.tree(d, {}, "kindabsent")
    expect(d, "S5 legacy type without jail.local", lab.helper(d, t).get("legacy_jail_local"), "absent")

    # S6 leaks
    rec = "[recidive]\nenabled = true\nlogpath = @LOGS@/fail2ban.log\n"
    t = lab.tree(d, {"jail.local": rec}, "recidive")
    r = lab.helper(d, t)
    check(d, "S6 recidive without own values: leak reported",
          {"maxretry", "bantime.increment", "bantime.factor"} <= set(keyset(r["leaks"], "recidive")), r["leaks"])
    r = lab.helper(d, t, cand="empty", keys=())
    expect(d, "S6 recidive, fail2ban_defaults {}: leaks", r["leaks"], [])
    ngx = "[nginx-http-auth]\nenabled = true\nbackend = auto\n"
    t = lab.tree(d, {"jail.local": ngx}, "nginxfile")
    r = lab.helper(d, t)
    check(d, "S6 operator nginx jail: leak reported", "maxretry" in keyset(r["leaks"], "nginx-http-auth"),
          r["leaks"])
    r = lab.helper(d, t, jails=("sshd", "nginx-http-auth", "nginx-botsearch"))
    expect(d, "S6 same jail when auto_sec's nginx file owns it: no leak", r["leaks"], [])

    # S7 addresses auto_sec wants ignored
    t = lab.tree(d, {"jail.local": "[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 198.51.100.0/24\n"}, "ignore")
    r = lab.helper(d, t, cand="ips", ips=("203.0.113.7", "198.51.100.9", "2001:db8::/32"))
    expect(d, "S7 [DEFAULT] ignoreip of yours: missing (CIDR-aware)", r["ignore_missing"],
           ["203.0.113.7", "2001:db8::/32"])
    t = lab.tree(d, {"jail.local": "[sshd]\nignoreip = 10.9.9.9\n"}, "ignoresshd")
    r = lab.helper(d, t, cand="ips", ips=("203.0.113.7", "198.51.100.9", "2001:db8::/32"))
    expect(d, "S7 [sshd] ignoreip of yours: all missing", r["ignore_missing"],
           ["203.0.113.7", "198.51.100.9", "2001:db8::/32"])
    t = lab.tree(d, {}, "ignorestock")
    r = lab.helper(d, t, cand="ips", ips=("203.0.113.7", "198.51.100.9", "2001:db8::/32"))
    expect(d, "S7 stock: auto_sec's addresses are ignored", r["ignore_missing"], [])
    expect(d, "S7 stock: ignoreip is not a leak", r["leaks"], [])

    # S8 port
    t = lab.tree(d, {"jail.local": "[sshd]\nport = 2200\n"}, "port2200")
    r = lab.helper(d, t)
    expect(d, "S8 [sshd] port 2200 with ssh_port 22: port_ok", (r["sshd"]["port_ok"], r["sshd"]["action_ports"]),
           (False, ["2200"]))
    t = lab.tree(d, {"jail.local": "[sshd]\nport = ssh,2222\n"}, "portboth")
    r = lab.helper(d, t, cand="port2222", ssh_port=2222)
    expect(d, "S8 [sshd] port ssh,2222 with ssh_port 2222: port_ok", r["sshd"]["port_ok"], True)

    # S9 files read before auto_sec's (R5)
    def r5(files, label):
        tt = lab.tree(d, files, "r5")
        return [(o["file"], o["section"], o["key"]) for o in lab.helper(d, tt)["read_before_overrides"]]
    expect(d, "S9 stock: nothing", r5({}, "stock"), [])
    expect(d, "S9 jail.d/0-early.conf [DEFAULT] maxretry",
           r5({"jail.d/0-early.conf": "[DEFAULT]\nmaxretry = 9\n"}, "a"), [("jail.d/0-early.conf", "DEFAULT", "maxretry")])
    expect(d, "S9 jail.d/0-early.conf [sshd] maxretry (beats [DEFAULT] anyway)",
           r5({"jail.d/0-early.conf": "[sshd]\nmaxretry = 9\n"}, "b"), [])
    expect(d, "S9 jail.d/0-early.conf [sshd] port",
           r5({"jail.d/0-early.conf": "[sshd]\nport = 2200\n"}, "c"), [("jail.d/0-early.conf", "sshd", "port")])
    expect(d, "S9 jail.d/0-early.conf [DEFAULT] maxretry = 4 (same value)",
           r5({"jail.d/0-early.conf": "[DEFAULT]\nmaxretry = 4\n"}, "d"), [])
    jc = read(os.path.join(lab.x(d), "etc/fail2ban/jail.conf")) + "\n# edited\n"
    got = r5({"jail.conf": jc}, "e")
    check(d, "S9 edited jail.conf: its [DEFAULT] values are reported",
          ("jail.conf", "DEFAULT", "maxretry") in got and ("jail.conf", "DEFAULT", "bantime") in got, got)
    t = lab.tree(d, {}, "r5po")
    with open(os.path.join(t, "paths-overrides.local"), "a", encoding="utf-8") as f:
        f.write("bantime = 2h\n")
    got = [(o["file"], o["key"]) for o in lab.helper(d, t)["read_before_overrides"]]
    expect(d, "S9 paths-overrides.local [DEFAULT] bantime", got, [("paths-overrides.local", "bantime")])
    expect(d, "S9 auto_sec's own nginx file (read before) is not reported",
           r5({"jail.d/" + NGINX: read(lab.cand["nginx"])}, "f"), [])

    # S10 broken live config
    t = lab.tree(d, {"jail.local": "[sshd]\nignoreip = %(known/ignoreip)s 10.1.1.1\n"}, "broken")
    r = lab.helper(d, t)
    check(d, "S10 broken live config: live not ok, error names it",
          (not r["live"]["ok"]) and "known/ignoreip" in r["live"]["error"], r["live"])

    # S11 why auto_sec never writes %(known/...)s
    kc = os.path.join(lab.w, "cand-known.conf")
    write(kc, MARKER + "\n[sshd]\nenabled = true\nignoreip = %(known/ignoreip)s 192.0.2.10\n")
    t = lab.tree(d, {}, "known1")
    r = lab.helper(d, t, cand=kc)
    check(d, "S11 known/ on a stock config breaks the whole config",
          (not r["new"]["ok"]) and "known/ignoreip" in r["new"]["error"], r["new"])
    t = lab.tree(d, {"jail.local": "[DEFAULT]\nignoreip = 127.0.0.1/8\n[sshd]\nignoreip = %(known/ignoreip)s 10.1.1.1\n"},
                 "known2")
    r = lab.helper(d, t, cand=kc)
    check(d, "S11 known/ next to an operator's known/ breaks the config",
          not r["new"]["ok"] or not r["new_test"]["ok"], r["new"])

    # S14 braces from the host never leave the helper
    t = lab.tree(d, {"jail.local": "[sshd]\nignoreip = 127.0.0.1/8 ::1 {{lookup('pipe','id')}}\n"}, "braces")
    r = lab.helper(d, t)
    leaked = [s for s in strings(r) if "{" in s or "}" in s]
    check(d, "S14 no '{' or '}' in any string the helper prints", not leaked and bool(r), leaked)


def template_checks(lab):
    c = {k: read(v) for k, v in lab.cand.items()}
    for k, txt in c.items():
        check("render", "S12 %s: marker is line 1" % k, txt.splitlines()[0].startswith("# Written by auto_sec (role 0"))
        if k.startswith("slow") and k != "slow-db":
            # The slow file's only "%" are fail2ban's own references, each to
            # an option that exists in every config (S17 loads them on all builds).
            rest = "\n".join(ln for ln in txt.splitlines() if not ln.startswith("#"))
            for ref in SLOW_REFS:
                rest = rest.replace(ref, "")
            check("render", "S12 %s: no '%%' besides the fixed references to the sshd jail and [DEFAULT]" % k,
                  "%" not in rest, [ln for ln in rest.splitlines() if "%" in ln])
            continue
        check("render", "S12 %s: no '%%' anywhere" % k, "%" not in txt)
        check("render", "S12 %s: no known/ reference" % k, "known/" not in txt)
    check("render", "S12 default: booleans lowercase", "bantime.increment = true\n" in c["default"])
    check("render", "S12 default: no ignoreip without addresses", "ignoreip" not in c["default"])
    check("render", "S12 empty: no [DEFAULT] section", "\n[DEFAULT]\n" not in c["empty"])
    expect("render", "S12 ips: ignoreip line",
           [ln for ln in c["ips"].splitlines() if ln.startswith("ignoreip")],
           ["ignoreip = 127.0.0.1/8 ::1 203.0.113.7 198.51.100.9 2001:db8::/32"])
    check("render", "S12 port2222: port line", "\n[sshd]\nenabled = true\nport = 2222\n" in c["port2222"])
    expect("render", "S12 nginx: sections",
           re.findall(r"^\[(.*)\]$", c["nginx"], re.M), ["nginx-http-auth", "nginx-botsearch"])
    expect("render", "S12 nginx: backend = auto twice", c["nginx"].count("\nbackend = auto\n"), 2)
    expect("render", "S12 slow: sections (no [DEFAULT] without addresses of yours)",
           re.findall(r"^\[(.*)\]$", c["slow"], re.M), ["sshd-slow", "recidive"])
    expect("render", "S12 slow-norec: sections", re.findall(r"^\[(.*)\]$", c["slow-norec"], re.M), ["sshd-slow"])
    expect("render", "S12 slow-ips: sections", re.findall(r"^\[(.*)\]$", c["slow-ips"], re.M), ["DEFAULT", "sshd-slow", "recidive"])
    expect("render", "S12 slow-norec is slow without its recidive section, byte for byte",
           c["slow"].startswith(c["slow-norec"]) and c["slow"][len(c["slow-norec"]):].lstrip("\n").startswith("# An address"), True)
    check("render", "S12 slow: sshd-slow 6 / 1d / 1w on ssh_port, recidive 3 / 1w / 4w with backend = auto",
          "\n[sshd-slow]\nenabled = true\nfilter = sshd\nbackend = %(sshd/backend)s\nlogpath = %(sshd/logpath)s\n"
          "banaction = %(sshd/banaction)s\nport = 22\nmaxretry = 6\nfindtime = 1d\nbantime = 1w\n\n" in c["slow"]
          and c["slow"].endswith("\n[recidive]\nenabled = true\nbackend = auto\nbanaction = %(banaction_allports)s\n"
                                 "maxretry = 3\nfindtime = 1w\nbantime = 4w\n"), c["slow"][-700:])
    check("render", "S12 slow: no ignoreip line at all without addresses of yours",
          not [ln for ln in c["slow"].splitlines() if ln.startswith("ignoreip")])
    check("render", "S12 slow-ips: [DEFAULT] holds one line, an empty ignoreip", "\n[DEFAULT]\nignoreip =\n\n" in c["slow-ips"])
    expect("render", "S12 slow-ips: your addresses follow the list each jail takes over",
           [ln for ln in c["slow-ips"].splitlines() if ln.startswith("ignoreip")],
           ["ignoreip =", "ignoreip = %(sshd/ignoreip)s 203.0.113.7 198.51.100.9 2001:db8::/32",
            "ignoreip = %(known/ignoreip)s 203.0.113.7 198.51.100.9 2001:db8::/32"])
    expect("render", "S12 slow-perm: bantime = -1 twice", c["slow-perm"].count("\nbantime = -1\n"), 2)
    expect("render", "S12 slow-db: one value, the token for the seconds",
           [ln for ln in c["slow-db"].splitlines() if ln and not ln.startswith("#")],
           ["[DEFAULT]", "dbpurgeage = @AUTOSEC_DBPURGEAGE@"])
    rc, out, err = run([sys.executable, "-I", "-c", "import ast,sys; ast.parse(open(sys.argv[1]).read(), "
                        "feature_version=(3, 10))", lab.a.helper])
    expect("helper", "S14 parses as Python 3.10", (rc, err.strip()), (0, ""))
    txt = read(lab.a.helper)
    check("helper", "S14 no Jinja delimiters in the helper (it travels inside an argv)",
          not re.search(r"\{\{|\{%|\{#", txt))


# --- S17-S21: the slow-scanner files (fail2ban_slow_scanners), all builds ----------

def slow_files(extra=None):
    """An operator layout for the slow-scanner checks. The lab has no
    /var/log/fail2ban.log, so fail2ban's log target and the recidive
    section's logpath point at a lab file (neither is a key auto_sec sets)."""
    files = {"jail.d/zz-lab.local": REC_LOG, "fail2ban.local": F2B_LOG}
    files.update(extra or {})
    return files


def dump_cmds(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            try:
                out.append(ast.literal_eval(line))
            except (ValueError, SyntaxError):
                pass
    return out


def jail_cmds(cmds, jail):
    return [c for c in cmds if len(c) > 1 and c[1] == jail]


def jail_source(cmds, jail):
    """(backend, log files, journal match alternatives) as the -d dump has them."""
    back = [c[2] for c in cmds if c[0] == "add" and c[1] == jail]
    paths = sorted(c[3] for c in cmds if len(c) > 3 and c[1] == jail and c[2] == "addlogpath")
    alts = set()
    for c in cmds:
        if len(c) > 3 and c[1] == jail and c[2] == "addjournalmatch":
            alts |= {a.strip() for a in " ".join(c[3:]).split(" + ")}
    return back, paths, alts


def jail_actions(cmds, jail):
    return sorted(c[3] for c in cmds if c[0] == "multi-set" and c[1] == jail and c[2] == "action")


def tree_dumps(lab, d, t):
    """The helper's `without` and `new` copies, as raw command lists."""
    rc1, wo, _ = lab.dump(d, t + ".work/without")
    rc2, nw, _ = lab.dump(d, t + ".work/new")
    return rc1, rc2, dump_cmds(wo.replace(t + ".work/without", "T")), dump_cmds(nw.replace(t + ".work/new", "T"))


def slow_config_checks(lab, d):
    canary, canary_jails = canary_of(lab, d)
    family = "iptables" if d in ("jammy", "bookworm") else "nftables"

    # S17 a stock layout: two more jails, and nothing else changes
    t = lab.tree(d, slow_files(), "slow-stock")
    r = lab.helper_slow(d, t, controller="192.0.2.200")
    if not r:
        return
    s = r["slow"]
    expect(d, "S17 stock + slow: live, new and -t load",
           (r["live"]["ok"], r["live_test"]["ok"], r["new"]["ok"], r["new_test"]["ok"]), (True, True, True, True))
    expect(d, "S17 stock + slow: jails after", sorted(r["new"]["jails"]), ["recidive", "sshd", "sshd-slow"])
    expect(d, "S17 stock + slow: the only changes are the two new jails",
           sorted((c["jail"], c["key"], c["after"]) for c in r["changes"]),
           [("recidive", "(jail)", "present"), ("sshd-slow", "(jail)", "present")])
    expect(d, "S17 stock + slow: no other jail changes, no ignored address dropped, nothing read before, sshd followed",
           (r["leaks"], r["ignore_dropped"], r["read_before_overrides"], s["follow"], s["foreign"], s["theirs_enabled"]),
           ([], [], [], [], [], False))
    j = s["jails"]
    expect(d, "S17 sshd-slow as fail2ban reads it: 6 in 1d, 1w",
           [j["sshd-slow"][k] for k in ("maxretry", "findtime", "bantime", "findtime_s", "bantime_s", "yours")],
           ["6", "1d", "1w", 86400, 604800, []])
    expect(d, "S17 recidive as fail2ban reads it: 3 in 1w, 4w, backend auto",
           [j["recidive"][k] for k in ("maxretry", "findtime", "bantime", "findtime_s", "bantime_s", "backend", "yours")],
           ["3", "1w", "4w", 604800, 2419200, "auto", []])
    expect(d, "S17 recidive is written and reads fail2ban's own log file",
           (s["recidive"]["write"], s["recidive"]["reason"], s["recidive"]["logpath"]),
           (True, "", [lab.logs + "/fail2ban.log"]))
    rc1, rc2, wo, nw = tree_dumps(lab, d, t)
    expect(d, "S17 raw -d dump of the sshd jail is identical",
           (rc1, rc2, jail_cmds(nw, "sshd") == jail_cmds(wo, "sshd"), len(jail_cmds(wo, "sshd")) > 10), (0, 0, True, True))
    a_src, b_src = jail_source(nw, "sshd"), jail_source(nw, "sshd-slow")
    expect(d, "S17 sshd-slow reads where sshd reads: same backend and log files",
           (b_src[0], b_src[1]), (a_src[0], a_src[1]))
    check(d, "S17 sshd-slow's journal matches cover the sshd jail's (%s)" % " + ".join(sorted(a_src[2])),
          a_src[2] <= b_src[2], (a_src[2], b_src[2]))
    expect(d, "S17 sshd-slow bans with the sshd jail's action; recidive with the all-ports one of the same family",
           (jail_actions(nw, "sshd-slow"), [x.split("-")[0] for x in jail_actions(nw, "recidive")],
            j["sshd-slow"]["families"], j["recidive"]["families"]),
           (jail_actions(nw, "sshd"), [family], [family], [family]))
    expect(d, "S17 no address of yours named: empty ignore lists, the controller is not covered",
           (j["sshd-slow"]["ignoreip"], j["recidive"]["ignoreip"], s["controller_open"]),
           ([], [], ["sshd-slow", "recidive"]))
    expect(d, "S17 the two files as tried differ from the host's (none yet)", s["differs"], {"db": True, "jail": True})
    with open(lab.cand["slow"], "rb") as fh:
        expect(d, "S17 sha256 of the jail file as tried", s["sha256"]["jail"], hashlib.sha256(fh.read()).hexdigest())
    want_db = read(lab.cand["slow-db"]).replace("@AUTOSEC_DBPURGEAGE@", "2592000").encode()
    expect(d, "S17 sha256 of the fail2ban.d file as tried (the token replaced by the seconds)",
           s["sha256"]["db"], hashlib.sha256(want_db).hexdigest())

    # your addresses, on top of the list each jail takes over
    r = lab.helper_slow(d, t, cand="slow-ips", alt="slow-ips-norec", ips=IPS, controller="198.51.100.9")
    s = r["slow"]
    expect(d, "S17 stock + your addresses: both jails ignore them; the controller is covered",
           (s["jails"]["sshd-slow"]["ignoreip"], s["jails"]["recidive"]["ignoreip"], s["ignore_missing"], s["controller_open"]),
           (list(IPS), list(IPS), {"recidive": [], "sshd-slow": []}, []))
    rc1, rc2, wo, nw = tree_dumps(lab, d, t)
    expect(d, "S17 ... the empty [DEFAULT] ignoreip that makes this possible: the sshd jail gets one empty addignoreip, "
              "nothing else, and no leak is reported",
           (rc1, rc2, [c for c in jail_cmds(nw, "sshd") if c not in jail_cmds(wo, "sshd")],
            [c for c in jail_cmds(wo, "sshd") if c not in jail_cmds(nw, "sshd")], r["leaks"]),
           (0, 0, [["set", "sshd", "addignoreip"]], [], []))

    # the canary's layout: its own recidive stays, only sshd-slow is added
    t = lab.tree(d, {"jail.local": canary, "fail2ban.local": F2B_LOG}, "slow-canary")
    r = lab.helper_slow(d, t, cand="slow-ips", alt="slow-ips-norec", ips=IPS)
    s = r["slow"]
    expect(d, "S17 canary: recidive is yours, auto_sec adds none",
           (s["recidive"]["theirs"], s["recidive"]["write"], s["recidive"]["reason"],
            s["recidive"]["detail"].startswith("jail.local [recidive]")), (True, False, "yours", True))
    expect(d, "S17 canary: jails after", r["new"]["jails"], canary_jails + ["sshd-slow"])
    expect(d, "S17 canary: the only change is sshd-slow; no leak, nothing dropped",
           ([(c["jail"], c["key"]) for c in r["changes"]], r["leaks"], r["ignore_dropped"], s["follow"]),
           ([("sshd-slow", "(jail)")], [], [], []))
    rc1, rc2, wo, nw = tree_dumps(lab, d, t)
    expect(d, "S17 canary: raw -d dump of every jail of yours is identical",
           (rc1, rc2, [x for x in canary_jails if jail_cmds(wo, x) != jail_cmds(nw, x)]), (0, 0, []))
    v = s["jails"]["sshd-slow"]
    expect(d, "S17 canary: sshd-slow takes over your ignoreip and adds your addresses",
           v["ignoreip"], ["127.0.0.1/8", "::1", "198.51.100.1", "203.0.113.2"] + list(IPS))
    expect(d, "S17 canary: sshd-slow inherits bantime.increment and the 8w cap from your [DEFAULT]",
           (v["increment"], v["maxtime"], v["factor"]), (True, "8w", "1"))
    expect(d, "S19 canary: dbpurgeage is 8w, your bantime.maxtime (longer than 30d)",
           [s["dbpurgeage"][k] for k in ("why", "why_value", "write_s", "new_s", "effective", "uncapped")],
           ["maxtime", "8w", 4838400, 4838400, True, []])
    check(d, "S19 canary: every jail with that cap is named", "sshd" in s["dbpurgeage"]["why_jails"],
          s["dbpurgeage"]["why_jails"])

    # S17 b ignore lists of yours
    def ign(files, name):
        tt = lab.tree(d, slow_files(files), "slow-ign-" + name)
        rr = lab.helper_slow(d, tt, cand="slow-ips", alt="slow-ips-norec", ips=IPS)
        return rr, rr["slow"]
    r, s = ign({"jail.local": "[sshd]\nignoreip = 10.9.9.9\n"}, "sshd")
    expect(d, "S17 [sshd] ignoreip of yours: sshd-slow takes it over, recidive has [DEFAULT]'s (none)",
           (s["jails"]["sshd-slow"]["ignoreip"], s["jails"]["recidive"]["ignoreip"], s["follow"], r["leaks"]),
           (["10.9.9.9"] + list(IPS), list(IPS), [], []))
    tt = lab.tree(d, slow_files({"jail.local": "[sshd]\nignoreip = 10.9.9.9\n"}), "slow-ign-sshd-none")
    expect(d, "S20 [sshd] ignoreip of yours and no address named in auto_sec's variables: sshd-slow would not ignore it (R03-F11)",
           lab.helper_slow(d, tt)["slow"]["follow"], ["ignoreip: sshd-slow would not ignore 10.9.9.9"])
    r, s = ign({"jail.local": "[DEFAULT]\nignoreip = 198.51.100.1\n[sshd]\nignoreip = %(known/ignoreip)s 10.9.9.9\n"}, "known")
    expect(d, "S17 [sshd] ignoreip that extends [DEFAULT]'s: sshd-slow has all of it",
           (s["jails"]["sshd-slow"]["ignoreip"], s["jails"]["recidive"]["ignoreip"], s["follow"]),
           (["198.51.100.1", "10.9.9.9"] + list(IPS), ["198.51.100.1"] + list(IPS), []))
    r, s = ign({"jail.d/0-early.conf": "[DEFAULT]\nignoreip = 192.0.2.9\n"}, "early")
    expect(d, "S20 an ignoreip in a file read before auto_sec's would be cancelled: reported three ways (R03-F5, R03-F10)",
           ([(o["file"], o["section"], o["key"]) for o in r["read_before_overrides"]], r["leak_lines"], r["ignore_dropped"]),
           ([("jail.d/0-early.conf", "DEFAULT", "ignoreip")], ["sshd.addignoreip: 192.0.2.9 -> (unset)"],
            [{"addresses": ["192.0.2.9"], "jail": "sshd"}]))
    jc = read(os.path.join(lab.x(d), "etc/fail2ban/jail.conf")).replace(
        "#ignoreip = 127.0.0.1/8 ::1", "ignoreip = 127.0.0.1/8 ::1 192.0.2.9", 1)
    r, s = ign({"jail.conf": jc}, "jailconf")
    got = [(o["file"], o["section"], o["key"]) for o in r["read_before_overrides"]]
    expect(d, "S20 an ignoreip in an edited jail.conf: reported, and sshd would stop ignoring the address; "
              "jail.conf's own [recidive] values (1w, 1d) are not yours and are not reported",
           (got, r["ignore_dropped"]), ([("jail.conf", "DEFAULT", "ignoreip")], [{"addresses": ["192.0.2.9"], "jail": "sshd"}]))
    r, s = ign({"jail.conf": jc.replace("[recidive]\n", "[recidive]\nmaxretry = 9\n", 1).replace("bantime  = 1w", "bantime  = 2w", 1)},
               "jailconf2")
    got = [(o["file"], o["section"], o["key"], o["value"]) for o in r["read_before_overrides"] if o["section"] == "recidive"]
    expect(d, "S20 recidive values of your own in an edited jail.conf (bantime 2w, maxretry 9): reported (R03-F5)",
           got, [("jail.conf", "recidive", "maxretry", "9"), ("jail.conf", "recidive", "bantime", "2w")])

    # S17 c the sshd jail's log source and ban action, set only in [sshd]
    def src(files, name, **kw):
        tt = lab.tree(d, slow_files(files), "slow-src-" + name)
        rr = lab.helper_slow(d, tt, **kw)
        return rr, rr["slow"], tree_dumps(lab, d, tt)[3]
    r, s, nw = src({"jail.local": "[sshd]\nbackend = systemd\n"}, "systemd")
    expect(d, "S17 [sshd] backend = systemd of yours: sshd-slow reads the journal too",
           (jail_source(nw, "sshd-slow")[0], s["follow"]), (["systemd"], []))
    r, s, nw = src({"jail.local": "[sshd]\nbackend = polling\nlogpath = @LOGS@/nginx/error.log\n"}, "logpath")
    expect(d, "S17 [sshd] backend and logpath of yours: sshd-slow reads the same file",
           (jail_source(nw, "sshd-slow")[:2], s["follow"]), ((["polling"], [lab.logs + "/nginx/error.log"]), []))
    r, s, nw = src({"jail.local": "[sshd]\nbackend = systemd\njournalmatch = _SYSTEMD_UNIT=other.service\n"}, "journal")
    check(d, "S20 a journalmatch of yours that the sshd filter's own does not cover: reported (R03-F11)",
          len(s["follow"]) == 1 and s["follow"][0].startswith("journalmatch: sshd reads _SYSTEMD_UNIT=other.service"),
          s["follow"])
    r, s, nw = src({"jail.local": "[sshd]\nbanaction = ufw\n"}, "sshd-ufw")
    expect(d, "S17 [sshd] banaction = ufw of yours: sshd-slow bans with ufw too",
           (jail_actions(nw, "sshd-slow"), s["jails"]["sshd-slow"]["actions"], s["follow"]),
           (["ufw"], ["ufw (port 22)"], []))
    expect(d, "S18 ... and recidive is left out: its all-ports action is another tool",
           (s["recidive"]["write"], s["recidive"]["reason"], s["recidive"]["detail"]),
           (False, "action", "recidive: %s; sshd: ufw" % family))

    # S18 recidive: when it is left out
    def rec(files, name, **kw):
        tt = lab.tree(d, files, "slow-rec-" + name)
        rr = lab.helper_slow(d, tt, **kw)
        return rr, rr["slow"]
    r, s = rec(slow_files({"jail.local": "[DEFAULT]\nbanaction = ufw\n"}), "ufw")
    expect(d, "S18 banaction = ufw with the stock banaction_allports: recidive left out, only sshd-slow is added",
           (s["recidive"]["write"], s["recidive"]["reason"], sorted(r["new"]["jails"]), r["leaks"]),
           (False, "action", ["sshd", "sshd-slow"], []))
    r, s = rec(slow_files({"jail.local": "[DEFAULT]\nbanaction = ufw\nbanaction_allports = ufw\n"}), "ufw2")
    expect(d, "S18 banaction_allports = ufw too: recidive is written, with ufw",
           (s["recidive"]["write"], s["recidive"]["reason"], s["jails"]["recidive"]["families"]), (True, "", ["ufw"]))
    r, s = rec({"jail.d/zz-lab.local": REC_LOG, "fail2ban.local": "[Definition]\nlogtarget = SYSLOG\n"}, "syslog")
    expect(d, "S18 fail2ban logs to SYSLOG: recidive left out",
           (s["recidive"]["write"], s["recidive"]["reason"], s["recidive"]["logtarget"]), (False, "logtarget", "SYSLOG"))
    r, s = rec({"jail.d/zz-lab.local": REC_LOG, "fail2ban.local": "[Definition]\nlogtarget = @LOGS@/auth.log\n"}, "otherlog")
    expect(d, "S18 fail2ban logs to another file than recidive reads: recidive left out",
           (s["recidive"]["write"], s["recidive"]["reason"]), (False, "logtarget"))
    r, s = rec(slow_files({"jail.local": "[recidive]\nenabled = false\n"}), "disabled")
    expect(d, "S18 a file of yours turns recidive off: left out, your file is named",
           (s["recidive"]["write"], s["recidive"]["reason"], s["recidive"]["detail"]),
           (False, "disabled", "jail.local [recidive] false"))
    r, s = rec(slow_files(), "off", cand="slow-norec", alt=None)
    expect(d, "S18 fail2ban_slow_recidive_enabled: false: no recidive jail, nothing about it",
           (s["recidive"]["wanted"], s["recidive"]["reason"], sorted(r["new"]["jails"]), sorted(s["jails"])),
           (False, "off", ["sshd", "sshd-slow"], ["sshd-slow"]))
    mine = {SLOW_REL: read(lab.cand["slow"]), DB_REL: read(lab.cand["slow-db"]).replace("@AUTOSEC_DBPURGEAGE@", "2592000")}
    r, s = rec(slow_files(mine), "second")
    expect(d, "S17 second run on auto_sec's own files: no change at all, files identical",
           (r["changes"], r["leaks"], s["differs"], s["dbpurgeage"]["changes"]), ([], [], {"db": False, "jail": False}, False))
    r, s = rec(slow_files(mine), "withdrawn", cand="slow-norec", alt=None)
    expect(d, "S18 the sub-switch turned off later: auto_sec's own recidive goes, and that is no leak",
           ([(c["jail"], c["key"], c["after"]) for c in r["changes"]], r["leaks"]),
           ([("recidive", "(jail)", "absent")], []))
    own = dict(mine)
    own["jail.local"] = "[recidive]\nenabled = true\nbantime = 2w\n"
    r, s = rec(slow_files(own), "taken-over")
    check(d, "S18 you enable a recidive of your own later: auto_sec's section would go and change your jail (R03-F10)",
          s["recidive"]["reason"] == "yours" and jailset(r["leaks"]) == ["recidive"]
          and {"findtime", "maxretry"} <= set(keyset(r["leaks"], "recidive")), (s["recidive"], r["leak_lines"]))

    # S19 dbpurgeage: the largest of your minimum, what the jails need, and what the server has
    def dbp(files, name, **kw):
        tt = lab.tree(d, files, "slow-db-" + name)
        rr = lab.helper_slow(d, tt, **kw)
        return rr["slow"]["dbpurgeage"]
    v = dbp(slow_files(), "stock")
    expect(d, "S19 stock: 1d becomes 30d (your minimum), set by auto_sec's file",
           [v[k] for k in ("without", "without_s", "why", "write_s", "new_s", "effective", "changes", "set_in")],
           ["1d", 86400, "variable", 2592000, 2592000, True, True, DB_REL + " [DEFAULT] 2592000"])
    v = dbp(slow_files(), "min1y", db_min="1y")
    expect(d, "S19 fail2ban_slow_dbpurgeage: 1y", (v["why"], v["write_s"], v["new_s"]), ("variable", 31557600, 31557600))
    v = dbp({"jail.d/zz-lab.local": REC_LOG, "fail2ban.local": F2B_LOG + "dbpurgeage = 12h\n"}, "own-short")
    expect(d, "S19 your fail2ban.local says 12h in [Definition]: it wins, the server keeps 12h",
           [v[k] for k in ("write_s", "new_s", "effective", "changes", "set_in")],
           [2592000, 43200, False, False, "fail2ban.local [Definition] 12h"])
    v = dbp({"jail.d/zz-lab.local": REC_LOG, "fail2ban.local": "[DEFAULT]\ndbpurgeage = 12h\n" + F2B_LOG}, "own-short2")
    expect(d, "S19 your fail2ban.local says 12h in [DEFAULT]: it is read later and wins too",
           [v[k] for k in ("write_s", "new_s", "effective", "set_in")],
           [2592000, 43200, False, "fail2ban.local [DEFAULT] 12h"])
    v = dbp({"jail.d/zz-lab.local": REC_LOG, "fail2ban.local": F2B_LOG + "dbpurgeage = 90d\n"}, "own-long")
    expect(d, "S19 your fail2ban.local says 90d: kept, never shortened",
           [v[k] for k in ("why", "why_value", "write_s", "new_s", "changes")], ["yours", "90d", 7776000, 7776000, False])
    fc = read(os.path.join(lab.x(d), "etc/fail2ban/fail2ban.conf")).replace("dbpurgeage = 1d", "dbpurgeage = 90d", 1)
    v = dbp(slow_files({"fail2ban.conf": fc}), "conf-long")
    expect(d, "S19 90d in an edited fail2ban.conf (read BEFORE auto_sec's file): auto_sec writes 90d, not 30d",
           [v[k] for k in ("why", "write_s", "new_s", "effective")], ["yours", 7776000, 7776000, True])
    v = dbp(slow_files({"fail2ban.d/00-aaa.conf": "[DEFAULT]\ndbpurgeage = 60d\n"}), "early-long")
    expect(d, "S19 60d in a fail2ban.d file read before auto_sec's: never shortened either",
           [v[k] for k in ("why", "write_s", "new_s")], ["yours", 5184000, 5184000])
    v = dbp(slow_files({"jail.local": "[sshd]\nbantime = 12w\n"}), "long-ban")
    expect(d, "S19 a jail of yours bans for 12w: dbpurgeage follows",
           [v[k] for k in ("why", "why_jail", "why_value", "write_s", "new_s")], ["bantime", "sshd", "12w", 7257600, 7257600])
    v = dbp(slow_files({"jail.local": "[sshd]\nfindtime = 10w\n"}), "long-find")
    expect(d, "S19 a jail of yours looks back 10w: dbpurgeage follows",
           [v[k] for k in ("why", "why_jail", "write_s")], ["findtime", "sshd", 6048000])
    v = dbp(slow_files({"jail.local": "[DEFAULT]\nbantime.increment = true\nbantime.maxtime = 26w\n"}), "maxtime")
    expect(d, "S19 ban times grow up to bantime.maxtime 26w: dbpurgeage follows",
           [v[k] for k in ("why", "why_value", "write_s", "uncapped")], ["maxtime", "26w", 15724800, []])
    v = dbp(slow_files({"jail.d/" + OWN: read(lab.cand["default"])}), "uncapped")
    expect(d, "S19 auto_sec's own fail2ban_defaults (bantime.increment, no bantime.maxtime): growth has no cap, 30d stays",
           [v[k] for k in ("why", "write_s", "uncapped")], ["variable", 2592000, ["recidive", "sshd", "sshd-slow"]])
    v = dbp(slow_files({"jail.local": "[sshd]\nbantime = 20y\n"}), "huge")
    expect(d, "S19 a ban time above ten years is not counted", (v["write_s"], v["uncounted"]), (2592000, ["sshd bantime 20y"]))
    tt = lab.tree(d, slow_files(), "slow-perm")
    r = lab.helper_slow(d, tt, cand="slow-perm", alt="slow-norec")
    s = r["slow"]
    expect(d, "S19 bantime -1 in both jails: fail2ban loads it, and a ban until you unban needs no dbpurgeage",
           (r["new"]["ok"], r["new_test"]["ok"], s["jails"]["sshd-slow"]["bantime"], s["jails"]["recidive"]["bantime"],
            s["dbpurgeage"]["permanent"], s["dbpurgeage"]["write_s"], s["dbpurgeage"]["why"]),
           (True, True, "-1", "-1", ["recidive", "sshd-slow"], 2592000, "variable"))
    rc, out, err = run([lab.client(d), "--str2sec", "1d + 1w + 4w + 30d"])
    expect(d, "S19 fail2ban's own --str2sec adds up several times in one call (the helper's shortcut)",
           (rc, out.strip()), (0, str(86400 + 604800 + 2419200 + 2592000)))
    expect(d, "S19 --str2sec 1mo and 1y, as the helper counts them",
           [str(int(float(run([lab.client(d), "--str2sec", x])[1].strip()))) for x in ("1mo", "1y", "8w")],
           ["2629800", "31557600", "4838400"])
    tt = lab.tree(d, {"fail2ban.local": "[DEFAULT]\ndbpurgeage = 2d\n", DB_REL: "[DEFAULT]\ndbpurgeage = 2592000\n",
                      "fail2ban.d/zz-later.conf": "[DEFAULT]\ndbpurgeage = 3d\n"}, "slow-order")
    def server_value(conf, key):
        return [str(c[2]) for c in dump_cmds(lab.dump(d, conf)[1]) if c[0] == "set" and len(c) == 3 and c[1] == key]
    expect(d, "S1 fail2ban.d read order: fail2ban.conf, fail2ban.d/*.conf (sorted), then fail2ban.local",
           server_value(tt, "dbpurgeage"), ["2d"])
    os.unlink(os.path.join(tt, "fail2ban.local"))
    expect(d, "S1 ... a later fail2ban.d file beats auto_sec's 00-autosec.conf", server_value(tt, "dbpurgeage"), ["3d"])
    os.unlink(os.path.join(tt, "fail2ban.d/zz-later.conf"))
    expect(d, "S1 ... and auto_sec's file beats fail2ban.conf", server_value(tt, "dbpurgeage"), ["2592000"])

    # S20 a jail or section sshd-slow that is not auto_sec's
    def foreign(files, name):
        tt = lab.tree(d, slow_files(files), "slow-foreign-" + name)
        rr = lab.helper_slow(d, tt)
        return rr, rr["slow"]
    r, s = foreign({"jail.local": "[sshd-slow]\nenabled = true\nfilter = sshd\nlogpath = @LOGS@/auth.log\nmaxretry = 9\n"}, "jail")
    expect(d, "S20 your own enabled [sshd-slow] jail: reported (R03-F9)", (s["theirs_enabled"], s["foreign"]), (True, ["jail.local"]))
    r, s = foreign({"jail.local": "[sshd-slow]\nmaxretry = 9\n"}, "section")
    expect(d, "S20 a [sshd-slow] section of yours that only sets a value: reported too, and the value would win",
           (s["theirs_enabled"], s["foreign"], s["jails"]["sshd-slow"]["yours"]), (False, ["jail.local"], ["maxretry"]))
    r, s = foreign({"jail.d/zz-mine.local": "[sshd-slow]\nbantime = 2h\n"}, "jaild")
    expect(d, "S20 ... in a jail.d file", s["foreign"], ["jail.d/zz-mine.local"])
    tt = lab.tree(d, slow_files(), "slow-nodir")
    os.rmdir(os.path.join(tt, "fail2ban.d"))
    expect(d, "S20 fail2ban.d is missing: reported (R03-F2), although the trial copy loads",
           lab.helper_slow(d, tt)["slow"]["folders"], False)
    r, s = foreign({"jail.local": "[sshd]\nignoreip = 127.0.0.1/8 {{lookup('pipe','id')}}\n"}, "braces")
    leaked = [x for x in strings(r) if "{" in x or "}" in x]
    check(d, "S14 no '{' or '}' in any string of the slow trial", not leaked and bool(r), leaked)

    # S1 read order with all of auto_sec's jail files, and S6 the main file next to the slow file
    files = slow_files({"jail.d/" + OWN: read(lab.cand["ips"]), "jail.d/" + NGINX: read(lab.cand["nginx"]),
                        SLOW_REL: read(lab.cand["slow-ips"]), "jail.d/0-zero.conf": "[sshd]\nusedns = warn\n"})
    t = lab.tree(d, files, "slow-main")
    got = [f for f in lab.trace(d, t) if f.startswith("jail.d/0")]
    expect(d, "S1 read order: 00-autosec-nginx.conf, 00-autosec-slow.conf, 00-autosec.conf",
           got, ["jail.d/0-zero.conf", "jail.d/" + NGINX, SLOW_REL, "jail.d/" + OWN])
    r = lab.helper(d, t, cand="ips", ips=IPS, jails=("sshd", "nginx-http-auth", "nginx-botsearch", "sshd-slow", "recidive"),
                   own=(SLOW,))
    expect(d, "S6 the main file next to auto_sec's slow file: its [DEFAULT] values in sshd-slow and recidive are no leak",
           (r["new"]["ok"], r["new_test"]["ok"], r["leaks"], r["read_before_overrides"]), (True, True, [], []))
    r = lab.helper(d, t, cand="ips", ips=IPS)
    check(d, "S6 ... without telling the helper that the slow file is auto_sec's: leaks and a read-before report",
          {"recidive", "sshd-slow"} <= set(jailset(r["leaks"]))
          and (SLOW_REL, "DEFAULT", "ignoreip") in [(o["file"], o["section"], o["key"]) for o in r["read_before_overrides"]],
          (r["leak_lines"], r["read_before_overrides"]))
    nw = dump_cmds(lab.dump(d, t)[1])
    expect(d, "S17 your addresses in the main file's [DEFAULT] and again in sshd-slow: fail2ban loads the doubled list",
           [c[3:] for c in jail_cmds(nw, "sshd-slow") if len(c) > 2 and c[2] == "addignoreip"],
           [["127.0.0.1/8", "::1"] + list(IPS) + list(IPS)])


PURGE_CHILD = r'''
import sys, json, sqlite3, time, os, shutil
sys.path.insert(0, sys.argv[1])
path = sys.argv[2]
from fail2ban.server.database import Fail2BanDb
if os.path.exists(path):
    os.unlink(path)
Fail2BanDb(path)
now, day = int(time.time()), 86400
rows = [("192.0.2.1", 3, 28 * day), ("192.0.2.2", 3, 3600), ("192.0.2.3", 400, -1),
        ("192.0.2.4", 10, 7 * day), ("192.0.2.5", 23, 7 * day), ("192.0.2.6", 40, 3600)]
con = sqlite3.connect(path)
con.execute("INSERT INTO jails(name, enabled) VALUES ('sshd', 1)")
for ip, age, bantime in rows:
    for table in ("bans", "bips"):
        con.execute("INSERT INTO %s(jail, ip, timeofban, bantime, bancount, data) VALUES ('sshd', ?, ?, ?, 1, '{}')" % table,
                    (ip, now - age * day, bantime))
con.commit()
con.close()
out = {}
for age in ("1d", "30d"):
    copy = path + "." + age
    shutil.copy(path, copy)
    db = Fail2BanDb(copy)
    db.purgeage = age
    db.purge()
    con = sqlite3.connect(copy)
    out[age] = {t: sorted(r[0].split(".")[-1] for r in con.execute("SELECT ip FROM %s" % t)) for t in ("bans", "bips")}
    con.close()
print(json.dumps(out))
'''

GROWTH_CHILD = r'''
import sys, json
sys.path.insert(0, sys.argv[1])
from fail2ban.server.jail import Jail
from fail2ban.server.observer import ObserverThread
out = {}
for name, opts in (("factor2", [("increment", "true"), ("factor", "2")]), ("plain", [("increment", "true")]),
                   ("canary", [("increment", "true"), ("factor", "1"),
                               ("formula", "ban.Time * (1 << (ban.Count if ban.Count < 20 else 20))"), ("maxtime", "8w")])):
    jail = Jail("lab", "polling", None)
    for key, value in opts:
        jail.setBanTimeExtra(key, value)
    formula = jail.getBanTimeExtra()["evformula"]
    out[name] = {"max": jail.getMaxBanTime(),
                 "weeks": [formula(ObserverThread.BanTimeIncr(604800, n)) / 604800 for n in (1, 2, 3, 4, 20, 21, 50)]}
print(json.dumps(out))
'''


def code_checks(lab, d):
    """S21: fail2ban's own code of this build, run without a server: what a
    database purge deletes, and how ban times grow."""
    os.makedirs(os.path.join(lab.w, "db"), exist_ok=True)
    rc, out, err = run([sys.executable, "-I", "-B", "-c", PURGE_CHILD, lab.pypath(d), os.path.join(lab.w, "db", d + ".sqlite3")])
    got = json.loads(out.strip().splitlines()[-1]) if rc == 0 and out.strip() else {"error": err.strip()[-300:]}
    # rows: 1 = 4w ban, 3 days old; 2 = 1h ban, 3 days old; 3 = permanent, 400 days old;
    #       4 = 1w ban, 10 days old; 5 = 1w ban, 23 days old; 6 = 1h ban, 40 days old
    expect(d, "S21 purge with dbpurgeage 1d: every ban record older than 1d goes from `bans`; `bips` keeps the "
              "running ban (1), the permanent one (3), and a ban until 3 x its ban time + 1d are over (4, not 5)",
           got.get("1d"), {"bans": [], "bips": ["1", "3", "4"]})
    expect(d, "S21 purge with dbpurgeage 30d: `bans` keeps 30 days (the 400-day-old permanent ban's record goes); "
              "`bips` still remembers the 1h ban of 3 days ago (2) and the 1w ban of 23 days ago (5)",
           got.get("30d"), {"bans": ["1", "2", "4", "5"], "bips": ["1", "2", "3", "4", "5"]})
    rc, out, err = run([sys.executable, "-I", "-B", "-c", GROWTH_CHILD, lab.pypath(d)])
    got = json.loads(out.strip().splitlines()[-1]) if rc == 0 and out.strip() else {"error": err.strip()[-300:]}
    expect(d, "S21 growth of a 1w ban with auto_sec's fail2ban_defaults (increment, factor 2, no maxtime): "
              "4w, 8w, 16w, 32w ... no limit; the doubling stops at the 20th repeat",
           got.get("factor2"), {"max": -1, "weeks": [4.0, 8.0, 16.0, 32.0, 2097152.0, 2097152.0, 2097152.0]})
    expect(d, "S21 growth with bantime.increment alone", got.get("plain"),
           {"max": -1, "weeks": [2.0, 4.0, 8.0, 16.0, 1048576.0, 1048576.0, 1048576.0]})
    expect(d, "S21 growth with the canary's settings (bantime.maxtime 8w): 2w, 4w, then 8w for good",
           got.get("canary"), {"max": 4838400, "weeks": [2.0, 4.0, 8.0, 8.0, 8.0, 8.0, 8.0]})


# --- S13, S15, S16: a real fail2ban 1.0.2 server, as this user ---------------------

class Server:
    LAB_ACTION = ("[Definition]\nactionstart = echo \"start <name> port=<port>\" >> {r}/actions.log\n"
                  "actionstop = echo \"stop <name> port=<port>\" >> {r}/actions.log\nactioncheck =\n"
                  "actionban = echo \"ban <name> <ip> port=<port>\" >> {r}/actions.log\n"
                  "actionunban = echo \"unban <name> <ip> port=<port>\" >> {r}/actions.log\n")

    def __init__(self, lab, dist, conf, name, fresh=True, dbpurgeage="1d"):
        """dbpurgeage: the operator's own value in fail2ban.local; None = none
        (fail2ban.conf's 1d applies, and auto_sec's fail2ban.d file can change it)."""
        self.lab, self.dist, self.conf = lab, dist, conf
        self.r = os.path.join(lab.w, "srv", name)
        if fresh:
            shutil.rmtree(self.r, ignore_errors=True)
        os.makedirs(self.r, exist_ok=True)
        write(os.path.join(conf, "fail2ban.local"),
              "[Definition]\nloglevel = INFO\nlogtarget = %s/f2b.log\nsocket = %s/f2b.sock\n"
              "pidfile = %s/f2b.pid\ndbfile = %s/f2b.sqlite3\n" % ((self.r,) * 4)
              + ("dbpurgeage = %s\n" % dbpurgeage if dbpurgeage else ""))
        write(os.path.join(conf, "action.d/lab.conf"), self.LAB_ACTION.format(r=self.r))
        self.srv = os.path.join(lab.w, "bin", "f2bs-" + dist)
        with LOCK:  # servers of several checks may start side by side
            if not os.path.exists(self.srv):
                write(self.srv, "#!/bin/sh\ncd / || exit 2\nexec %s -I -B -c \"%s\" %s \"$@\"\n"
                      % (lab.a.server_python, SERVER_CODE, lab.pypath(dist)), 0o755)
        # f2b.log too: a recidive jail that reads the server's own log needs the
        # file before the server has written its first line.
        for f in ("auth.log", "rec.log", "auth2.log", "f2b.log"):
            if fresh or not os.path.exists(os.path.join(self.r, f)):
                write(os.path.join(self.r, f), "")

    def cli(self, *args):
        return run([self.lab.client(self.dist), "-c", self.conf] + list(args), timeout=120)

    def start(self):
        with open(os.path.join(self.r, "server.out"), "ab") as out:
            subprocess.Popen([self.srv, "-c", self.conf, "-xf", "start"], stdout=out, stderr=out,
                             stdin=subprocess.DEVNULL, cwd="/", start_new_session=True)
        for _ in range(100):
            if self.cli("ping")[0] == 0:
                return True
            time.sleep(0.2)
        bad(self.dist, "server did not start: " + read(os.path.join(self.r, "server.out"))[-600:])
        return False

    def stop(self):
        self.cli("stop")
        time.sleep(0.5)

    def pid(self):
        try:
            return read(os.path.join(self.r, "f2b.pid")).strip()
        except OSError:
            return ""

    def banned(self, jail):
        rc, out, err = self.cli("status", jail)
        m = re.search(r"Banned IP list:\s*(.*)$", out, re.M)
        return sorted(m.group(1).split()) if (rc == 0 and m) else None

    def jails(self):
        rc, out, err = self.cli("status")
        m = re.search(r"Jail list:\s*(.*)$", out, re.M)
        return sorted(x.strip() for x in m.group(1).split(",") if x.strip()) if (rc == 0 and m) else None

    def actions(self, clear=False):
        p = os.path.join(self.r, "actions.log")
        txt = read(p) if os.path.exists(p) else ""
        if clear:
            write(p, "")
        return [ln for ln in txt.splitlines() if ln]

    def log(self):
        return read(os.path.join(self.r, "f2b.log"))

    def get(self, *args):
        return self.cli("get", *args)[1].strip()

    def dbpurgeage(self):
        m = re.search(r"(-?[0-9]+)\s*seconds", self.cli("get", "dbpurgeage")[1])
        return int(m.group(1)) if m else None

    def ban_time(self, jail, ip):
        """Seconds this jail bans the address for (-1: until unbanned); None: not banned."""
        for ln in self.cli("get", jail, "banip", "--with-time")[1].splitlines():
            m = re.match(r"^\s*(\S+)\s.*\+\s*(-?[0-9]+)\s*=", ln)
            if m and m.group(1) == ip:
                return int(m.group(2))
        return None

    def fail(self, logfile, ip, n=3):
        stamp = time.strftime("%b %e %H:%M:%S")
        with open(os.path.join(self.r, logfile), "a", encoding="utf-8") as f:
            for i in range(n):
                f.write("%s lab sshd[%d]: Failed password for root from %s port %d ssh2\n"
                        % (stamp, 1000 + i, ip, 4000 + i))


def s13_server(lab, d):
    base = ("[DEFAULT]\nbanaction = lab\nbanaction_allports = lab\nbackend = polling\nignoreself = false\n"
            "[sshd]\nenabled = true\nlogpath = {r}/auth.log\nmaxretry = {mr}\nfindtime = 1h\nbantime = 1h\n{port}"
            "[recidive]\nenabled = true\nlogpath = {r}/rec.log\nbantime = 4w\nfindtime = 1d\nmaxretry = 2\n{extra}")
    sshd2 = "[sshd2]\nenabled = true\nfilter = sshd\nlogpath = {r}/auth2.log\nmaxretry = 2\nbantime = 1h\n"
    t = lab.tree(d, {"jail.d/defaults-debian.conf": None}, "s13")
    s = Server(lab, d, t, "s13")
    jl = lambda mr=2, extra="", port="": write(os.path.join(t, "jail.local"),  # noqa: E731
                                                base.format(r=s.r, mr=mr, port=port, extra=extra.format(r=s.r)))
    jl(extra=sshd2)
    if not s.start():
        return
    try:
        s.fail("auth.log", "203.0.113.5")
        s.fail("auth2.log", "203.0.113.6")
        s.cli("set", "recidive", "banip", "198.51.100.7")
        time.sleep(4)
        before = (s.banned("sshd"), s.banned("sshd2"), s.banned("recidive"))
        expect(d, "S13 bans in place", before, (["203.0.113.5"], ["203.0.113.6"], ["198.51.100.7"]))
        pid = s.pid()
        s.actions(clear=True)
        rc = s.cli("reload")[0]
        time.sleep(2)
        expect(d, "S13 plain reload, same config: bans kept, no action ran",
               (rc, (s.banned("sshd"), s.banned("sshd2"), s.banned("recidive")), s.actions(clear=True), s.pid()),
               (0, before, [], pid))
        jl(mr=3, extra=sshd2)
        rc = s.cli("reload")[0]
        time.sleep(2)
        expect(d, "S13 reload with maxretry 2 -> 3: applied, bans kept, no action ran",
               (rc, s.cli("get", "sshd", "maxretry")[1].strip(), s.banned("sshd"), s.actions(clear=True)),
               (0, "3", ["203.0.113.5"], []))
        jl(mr=3)
        rc = s.cli("reload")[0]
        time.sleep(2)
        acts = s.actions(clear=True)
        check(d, "S13 reload without jail sshd2: it is stopped and its IP unbanned",
              rc == 0 and s.jails() == ["recidive", "sshd"] and any(a.startswith("unban sshd2 203.0.113.6") for a in acts)
              and any(a.startswith("stop sshd2") for a in acts), (s.jails(), acts))
        write(os.path.join(t, "jail.d/zz-broken.local"), "[sshd]\nignoreip = %(known/ignoreip)s 10.1.1.1\n")
        rc = s.cli("reload")[0]
        time.sleep(1)
        expect(d, "S13 reload with a broken config: fails, old jails and bans stay",
               (rc != 0, s.jails(), s.banned("sshd"), s.banned("recidive"), s.actions(clear=True)),
               (True, ["recidive", "sshd"], ["203.0.113.5"], ["198.51.100.7"], []))
        os.unlink(os.path.join(t, "jail.d/zz-broken.local"))
        rc = s.cli("reload", "--restart")[0]
        time.sleep(3)
        acts = s.actions(clear=True)
        check(d, "S13 reload --restart: jails restarted, bans restored",
              rc == 0 and s.banned("sshd") == ["203.0.113.5"] and s.banned("recidive") == ["198.51.100.7"]
              and any(a.startswith("start sshd") for a in acts) and any(a.startswith("ban recidive 198.51.100.7") for a in acts),
              acts)
        s.stop()
        db = sqlite3.connect(os.path.join(s.r, "f2b.sqlite3"))
        old = int(time.time()) - 3 * 86400
        for tbl in ("bans", "bips"):
            db.execute("UPDATE %s SET timeofban=? WHERE ip='198.51.100.7'" % tbl, (old,))
        db.commit()
        db.close()
        s.actions(clear=True)
        if not s.start():
            return
        time.sleep(3)
        expect(d, "S13 a 3-day-old 4-week ban survives stop/start with dbpurgeage 1d",
               s.banned("recidive"), ["198.51.100.7"])
        s.actions(clear=True)
        jl(mr=3, port="port = 2222\n")
        s.cli("reload")
        time.sleep(2)
        acts = s.actions(clear=True)
        expect(d, "S13 port 22 -> 2222, plain reload: actionstart does NOT run again",
               [a for a in acts if a.startswith("start sshd")], [])
        s.cli("reload", "--restart", "sshd")
        time.sleep(2)
        acts = s.actions(clear=True)
        check(d, "S13 reload --restart sshd: started on port 2222, ban restored",
              "start sshd port=2222" in acts and "ban sshd 203.0.113.5 port=2222" in acts, acts)
        jl(mr=3, port="port = 2222\nignoreip = 127.0.0.1/8 203.0.113.5\n")
        s.cli("reload")
        time.sleep(2)
        rc, out, err = s.cli("get", "sshd", "ignoreip")
        check(d, "S13 new ignoreip by reload: applied, but the banned IP stays banned",
              "203.0.113.5" in out and s.banned("sshd") == ["203.0.113.5"], (out, s.banned("sshd")))
        s.cli("reload", "--restart", "sshd")
        time.sleep(2)
        expect(d, "S13 ... until the jail restarts", s.banned("sshd"), [])
    finally:
        s.stop()


def s15_drift(lab, d):
    jl = ("[DEFAULT]\nbanaction = lab\nbanaction_allports = lab\nbackend = polling\n"
          "ignoreip = 127.0.0.1/8 ::1 198.51.100.1\n[sshd]\nenabled = true\nlogpath = {r}/auth.log\n"
          "maxretry = 3\nbantime = 1h\n[recidive]\nenabled = true\nlogpath = {r}/rec.log\nbantime = 4w\nfindtime = 1d\n")
    t = lab.tree(d, {"jail.d/defaults-debian.conf": None}, "s15")
    s = Server(lab, d, t, "s15")
    write(os.path.join(t, "jail.local"), jl.format(r=s.r))
    if not s.start():
        return
    try:
        # the default candidate changes recidive's bantime.factor etc., so drift is computed
        r = lab.helper(d, t, running=True, jails=("sshd", "recidive"))
        expect(d, "S15 running == files: same jails, no drift",
               (r["running"]["ok"], r["running"]["same_jails_as_disk"], r["running"]["drift"]), (True, True, []))
        with open(os.path.join(t, "jail.local"), "r+", encoding="utf-8") as f:
            txt = f.read().replace("maxretry = 3", "maxretry = 6")
            f.seek(0)
            f.write(txt)
            f.truncate()
        r = lab.helper(d, t, running=True, jails=("sshd", "recidive"))
        expect(d, "S15 jail.local edited, not reloaded: drift found",
               [(x["jail"], x["key"], x["running"], x["files"]) for x in r["running"]["drift"]],
               [("sshd", "maxretry", "3", "6")])
        s.cli("reload")
        time.sleep(2)
        s.cli("set", "sshd", "addignoreip", "192.0.2.55")
        marker = os.path.join(lab.w, "f2b-ignore")
        write(marker, "192.0.2.55\n")
        rc, out, err = run([sys.executable, "-I", lab.a.helper, "--verify", "--conf", t,
                            "--client", lab.client(d), "--runtime-ignore-file", marker])
        v = json.loads(out) if rc == 0 else {}
        expect(d, "S15 --verify after reload, role 02's runtime ignore is not drift",
               (rc, v.get("running", {}).get("same_jails_as_disk"), v.get("running", {}).get("drift")), (0, True, []))
        rc, out, err = run([sys.executable, "-I", lab.a.helper, "--verify", "--conf", t,
                            "--client", lab.client(d), "--runtime-ignore-file", marker + ".none"])
        v = json.loads(out) if rc == 0 else {}
        expect(d, "S15 --verify: an unknown runtime ignore is drift",
               [x["key"] for x in v.get("running", {}).get("drift", [])], ["ignoreip"])
    finally:
        s.stop()


# --- S16: role 03's task files, run by ansible-playbook ---------------------------

def s16_ansible(lab, d, playbook_bin):
    ptag = os.path.basename(os.path.dirname(os.path.dirname(playbook_bin)))
    tag = "S16 " + ptag
    os.makedirs(os.path.join(lab.w, ptag), exist_ok=True)
    # The ansible-core versions run side by side (main): each has its own
    # stubs, trees and servers, named with ptag.
    stubs = os.path.join(lab.w, ptag, "stubs")
    write(os.path.join(stubs, "dpkg-query"),
          "#!/bin/sh\n# lab stub: fail2ban 1.0.2 is installed\ncase \"$*\" in\n"
          "  *Version*) printf 'ii  1.0.2-3ubuntu0.1' ;;\n  *) printf 'ii ' ;;\nesac\n", 0o755)
    write(os.path.join(stubs, "systemctl"),
          "#!/bin/sh\n# lab stub: fail2ban.service active and enabled\ncase \"$1\" in\n"
          "  is-active) echo active ;;\n  is-enabled) echo enabled ;;\n  *) exit 1 ;;\nesac\n", 0o755)
    # The same, with fail2ban on hold (apt-mark hold): dpkg says "hi".
    stubs_held = os.path.join(lab.w, ptag, "stubs-held")
    write(os.path.join(stubs_held, "dpkg-query"),
          "#!/bin/sh\n# lab stub: fail2ban 1.0.2 is installed and held\ncase \"$*\" in\n"
          "  *Version*) printf 'hi  1.0.2-3ubuntu0.1' ;;\n  *) printf 'hi ' ;;\nesac\n", 0o755)
    shutil.copy(os.path.join(stubs, "systemctl"), os.path.join(stubs_held, "systemctl"))
    canary = read(os.path.join(lab.a.fixtures, "canary.jail.local")).replace("/var/log/", "@LOGS@/")
    legacy3 = read(os.path.join(lab.a.fixtures, "legacy-0.3.jail.local"))
    # The lab server cannot use nftables or the journal: a later file switches
    # every jail to the lab action and to log files (it sets no auto_sec key).
    zz = ("[DEFAULT]\nbanaction = lab\nbanaction_allports = lab\nbackend = polling\nignoreself = false\n"
          "[sshd]\nbackend = polling\nlogpath = {r}/auth.log\n")

    def case(name, jail_local, extra_vars=None, check_mode=False, extra_files=None, keep=None, after_start=None,
             held=False, nodb=False):
        """keep=(tree, server name): run again on the same tree, database and logs.
        after_start: files written once the server runs (edits it has not loaded).
        held: dpkg reports fail2ban as held ("hi"). nodb: dbfile = None."""
        files = {"jail.local": jail_local}
        files.update(extra_files or {})
        t = keep[0] if keep else lab.tree(d, files, "s16-%s-%s" % (ptag, name))
        s = Server(lab, d, t, keep[1] if keep else "s16-%s-%s" % (ptag, name), fresh=not keep)
        if nodb:
            p = os.path.join(t, "fail2ban.local")
            write(p, re.sub(r"(?m)^dbfile = .*$", "dbfile = None", read(p)))
        if not keep:
            write(os.path.join(t, "jail.d/zz-lab.local"), zz.format(r=s.r))
        if not s.start():
            return None
        s.cli("set", "sshd", "banip", "203.0.113.5")
        s.cli("set", "recidive", "banip", "198.51.100.7")
        time.sleep(1)
        for rel, content in (after_start or {}).items():
            write(os.path.join(t, rel), content.replace("@LOGS@", lab.logs))
        env = dict(os.environ, LC_ALL="C.UTF-8", ANSIBLE_NOCOLOR="1", ANSIBLE_RETRY_FILES_ENABLED="False",
                   ANSIBLE_LOCALHOST_WARNING="False", ANSIBLE_INVENTORY_UNPARSED_WARNING="False",
                   ANSIBLE_ROLES_PATH=lab.a.roles,
                   PATH=(stubs_held if held else stubs) + ":" + os.environ.get("PATH", ""))
        ev = {"_f2b_conf_dir": t, "_f2b_client": lab.client(d), "_f2b_conffiles_file": lab.conffiles(d),
              "_f2b_python": sys.executable, "_f2b_file_owner": os.environ.get("USER") or str(os.getuid()),
              "_f2b_run_dir": os.path.join(lab.w, ptag, "run-" + name),
              "_f2b_sim_dir": os.path.join(lab.w, ptag, "run-" + name, "f2b-sim"),
              "_f2b_prev_dir": os.path.join(lab.w, ptag, "run-" + name, "f2b-prev"),
              "_f2b_backup_dir": os.path.join(lab.w, ptag, "backup-" + name), "ssh_port": 22,
              # 0.6: fail2ban is managed only when asked for (keep by default).
              "fail2ban_hardening_enabled": True,
              "lab_plan_out": os.path.join(lab.w, ptag, "plan-%s.json" % name)}
        ev.update(extra_vars or {})
        evf = os.path.join(lab.w, ptag, "ev-%s.json" % name)
        write(evf, json.dumps(ev))
        before = {"pid": s.pid(), "sshd": s.banned("sshd"), "recidive": s.banned("recidive"),
                  "log": len(s.log()), "maxretry": s.cli("get", "sshd", "maxretry")[1].strip(),
                  "jail.local": (read(os.path.join(t, "jail.local"))
                                 if os.path.exists(os.path.join(t, "jail.local")) else None)}
        argv = [playbook_bin, os.path.join(lab.a.here, "ansible-lab.yml"), "-e", "@" + evf]
        if check_mode:
            argv.append("--check")
        s.actions(clear=True)
        rc, out, err = run(argv, env=env, cwd=lab.w)
        res = {"rc": rc, "out": out + err, "srv": s, "t": t, "before": before, "name": "s16-%s-%s" % (ptag, name)}
        res["after"] = {"pid": s.pid(), "sshd": s.banned("sshd"), "recidive": s.banned("recidive"),
                        "newlog": s.log()[before["log"]:], "actions": s.actions(), "jails": s.jails(),
                        "maxretry": s.cli("get", "sshd", "maxretry")[1].strip(),
                        "jail.local": (read(os.path.join(t, "jail.local"))
                                       if os.path.exists(os.path.join(t, "jail.local")) else None)}
        s.stop()
        write(os.path.join(lab.w, "s16-%s-%s.log" % (ptag, name)), out + err)
        res["plan"] = json.loads(read(ev["lab_plan_out"])) if os.path.exists(ev["lab_plan_out"]) else {}
        return res

    def own(t):
        p = os.path.join(t, "jail.d", OWN)
        return read(p) if os.path.exists(p) else None

    def recap(out):
        m = re.search(r"localhost\s*:\s*ok=\d+\s+changed=(\d+)\s+unreachable=\d+\s+failed=(\d+)", out)
        return (int(m.group(1)), int(m.group(2))) if m else None

    r = case("canary", canary)
    if r:
        a, b = r["after"], r["before"]
        expect(d, tag + " c1 canary: run ok, file written",
               (r["rc"], (own(r["t"]) or "").startswith(MARKER)), (0, True))
        expect(d, tag + " c1 canary: jail.local, bans, server PID untouched; no reload, no action",
               (a["jail.local"] == b["jail.local"], a["sshd"], a["recidive"], a["pid"] == b["pid"],
                "Reload" in a["newlog"], a["actions"]), (True, ["203.0.113.5"], ["198.51.100.7"], True, False, []))
        check(d, tag + " c1 canary: plan says no effective change", "no effective change, no reload" in r["out"],
              r["out"][-800:])
        expect(d, tag + " c1 without fail2ban_slow_scanners: no slow-scanner file, and the plan line as before 0.6.1",
               (os.path.exists(os.path.join(r["t"], SLOW_REL)), os.path.exists(os.path.join(r["t"], DB_REL)),
                r["plan"].get("line"), [i["what"].split(": ")[0].replace(r["t"], "") for i in r["plan"].get("plan", [])]),
               (False, False, "write 00-autosec.conf; no effective change, no reload", ["/jail.d/" + OWN]))
        t = r["t"]
        r2 = case("canary2", None, keep=(t, r["name"]))
        if r2:
            expect(d, tag + " c2 second run: nothing changed, no reload",
                   (r2["rc"], recap(r2["out"]), "Reload" in r2["after"]["newlog"]), (0, (0, 0), False))
    r = case("check", canary, check_mode=True)
    if r:
        expect(d, tag + " c12 --check on the canary layout: rc 0, no file written",
               (r["rc"], own(r["t"])), (0, None))
    r = case("stock", None)
    if r:
        a, b = r["after"], r["before"]
        expect(d, tag + " c3 stock: run ok, reloaded once, sshd ban and PID kept (no recidive jail in a stock layout)",
               (r["rc"], a["newlog"].count("Reload finished"), a["sshd"], a["pid"] == b["pid"]),
               (0, 1, ["203.0.113.5"], True))
        check(d, tag + " c3 stock: verify step passed", "fail2ban F10: verified" in r["out"], r["out"][-600:])
        check(d, tag + " c3 stock: report line", "sshd jail: maxretry 4, findtime 10m, bantime 1h, escalating" in r["out"],
              r["out"][-600:])
    r = case("leak", "[recidive]\nenabled = true\nlogpath = @LOGS@/fail2ban.log\n")
    if r:
        check(d, tag + " c5 leak: refused (R3), nothing written",
              r["rc"] != 0 and "would change jails of yours" in r["out"] and own(r["t"]) is None, r["out"][-600:])
    r = case("office", canary, {"office_static_ip": "203.0.113.7"})
    if r:
        check(d, tag + " c6 office IP hidden by your ignoreip: WARNING, run ok",
              r["rc"] == 0 and "WARNING: 203.0.113.7" in r["out"], r["out"][-600:])
    # (%(known/ignoreip)s would load here: the canary's [DEFAULT] sets ignoreip.)
    r = case("broken", canary, after_start={"jail.d/zz-broken.local": "[sshd]\nfindtime = %(autosec_no_such_option)s\n"})
    if r:
        check(d, tag + " c9 config broken after fail2ban started: refused (R1), nothing written, no reload",
              r["rc"] != 0 and "does not load" in r["out"] and own(r["t"]) is None
              and "Reload" not in r["after"]["newlog"], r["out"][-600:])
    r = case("foreign", canary, extra_files={"jail.d/" + OWN: "[sshd]\nmaxretry = 9\n"})
    if r:
        check(d, tag + " c11 foreign 00-autosec.conf: refused (R6), file kept",
              r["rc"] != 0 and "auto_sec never replaces a file it did not write" in r["out"]
              and own(r["t"]) == "[sshd]\nmaxretry = 9\n", r["out"][-600:])
    r = case("legacy", legacy3, {"ssh_port": 2222})
    if r:
        check(d, tag + " c4 0.3 jail.local without the switch: refused (R4), nothing changed",
              r["rc"] != 0 and "fail2ban_migrate_jail_local=true" in r["out"] and own(r["t"]) is None
              and r["after"]["jail.local"] == r["before"]["jail.local"], r["out"][-800:])
    r = case("migrate", legacy3, {"ssh_port": 2222, "fail2ban_migrate_jail_local": True})
    if r:
        bk = glob.glob(os.path.join(lab.w, ptag, "backup-migrate", "jail.local.auto_sec-0.x.*"))
        mode = stat.S_IMODE(os.stat(bk[0]).st_mode) if bk else None
        expect(d, tag + " c4 migrate: rc, jail.local gone, one backup 0600 identical, file written",
               (r["rc"], r["after"]["jail.local"], len(bk), mode, read(bk[0]) if bk else None,
                (own(r["t"]) or "").startswith(MARKER)),
               (0, None, 1, 0o600, legacy3, True))
        expect(d, tag + " c4 migrate: sshd ban kept, one reload", (r["after"]["sshd"],
               r["after"]["newlog"].count("Reload finished")), (["203.0.113.5"], 1))
    own_ign = legacy3.replace("[DEFAULT]\n", "[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 203.0.113.50\n", 1)
    r = case("migrate-ownign", own_ign, {"ssh_port": 2222, "fail2ban_migrate_jail_local": True})
    if r:
        check(d, tag + " c4b migrate a 0.3 file with your ignoreip line: refused (R4b), nothing changed",
              r["rc"] != 0 and "would make fail2ban stop ignoring 203.0.113.50" in r["out"]
              and own(r["t"]) is None and r["after"]["jail.local"] == r["before"]["jail.local"], r["out"][-800:])
    r = case("held", canary, held=True)
    if r:
        check(d, tag + " c17 fail2ban on hold (dpkg hi): counts as installed, preflight trial ran, file written",
              r["rc"] == 0 and "no effective change, no reload" in r["out"] and (own(r["t"]) or "").startswith(MARKER)
              and r["after"]["pid"] == r["before"]["pid"], r["out"][-800:])
    r = case("port22", None)
    if r:
        r2 = case("port2222", None, {"ssh_port": 2222}, keep=(r["t"], r["name"]))
        if r2:
            acts = r2["after"]["actions"]
            check(d, tag + " c10 ssh_port 22 -> 2222: sshd jail restarted on 2222, ban restored",
                  r2["rc"] == 0 and "start sshd port=2222" in acts and "ban sshd 203.0.113.5 port=2222" in acts,
                  (acts, r2["out"][-600:]))
            check(d, tag + " c10 with the database on: no W5 warning", "database is off" not in r2["out"],
                  r2["out"][-600:])
    r = case("nodb22", None, nodb=True)
    if r:
        r2 = case("nodb2222", None, {"ssh_port": 2222}, keep=(r["t"], r["name"]), nodb=True)
        if r2:
            check(d, tag + " c16 dbfile = None, ssh_port 22 -> 2222: W5 warns, and the restart releases the sshd ban",
                  r2["rc"] == 0 and "fail2ban's database is off" in r2["out"] and r2["after"]["sshd"] == [],
                  (r2["after"]["sshd"], r2["out"][-800:]))

    # Role 05's nginx jails (tasks/fail2ban-nginx.yml), then a second run.
    r = case("nginx", None, {"lab_nginx": True})
    if r:
        p = os.path.join(r["t"], "jail.d", NGINX)
        first = read(p).splitlines()[0] if os.path.exists(p) else None
        expect(d, tag + " c15 nginx jails: rc, marker, two reloads, jails, sshd ban kept",
               (r["rc"], first, r["after"]["newlog"].count("Reload finished"), r["after"]["jails"],
                r["after"]["sshd"]),
               (0, "# Written by auto_sec (role 05). Do not edit: the next run replaces this file.", 2,
                ["nginx-botsearch", "nginx-http-auth", "sshd"], ["203.0.113.5"]))
        r2 = case("nginx2", None, {"lab_nginx": True}, keep=(r["t"], r["name"]))
        if r2:
            expect(d, tag + " c15 second run (auto_sec's [DEFAULT] on its own nginx jails is no leak): "
                   "rc, nothing changed, no reload", (r2["rc"], recap(r2["out"]), "Reload" in r2["after"]["newlog"]),
                   (0, (0, 0), False))

    # Rollback: a client that fails `-t` on the real files (not on the trial
    # copies), and one whose first `reload` fails.
    real = lab.client(d)
    fail_t = os.path.join(lab.w, ptag, "f2bc-fail-t")
    write(fail_t, """#!/bin/sh
case "$*" in
  *f2b-sim*) ;;
  *" -t") echo 'ERROR   injected -t failure' >&2; exit 255 ;;
esac
exec %s "$@"
""" % real, 0o755)
    fail_reload = os.path.join(lab.w, ptag, "f2bc-fail-reload")
    flag = fail_reload + ".done"
    write(fail_reload, """#!/bin/sh
case "$*" in
  *" reload") if [ ! -e %s ]; then : > %s; echo 'ERROR   injected reload failure' >&2; exit 255; fi ;;
esac
exec %s "$@"
""" % (flag, flag, real), 0o755)
    r = case("rollback-t", None, {"_f2b_client": fail_t})
    if r:
        check(d, tag + " c13 -t fails on the real files: file removed again, no reload, run stops",
              r["rc"] != 0 and own(r["t"]) is None and "Put the previous file back." in r["out"]
              and "Reload" not in r["after"]["newlog"], r["out"][-800:])
    r = case("rollback-reload", None, {"_f2b_client": fail_reload})
    if r:
        check(d, tag + " c14 reload fails: file removed, previous config loaded again, bans kept",
              r["rc"] != 0 and own(r["t"]) is None and "Loaded the previous config again." in r["out"]
              and r["after"]["maxretry"] == r["before"]["maxretry"] and r["after"]["sshd"] == ["203.0.113.5"],
              (r["before"]["maxretry"], r["after"]["maxretry"], r["out"][-800:]))


# --- S22: the slow-scanner jails on a real server (fail2ban 1.0.2 and 1.1.0) ---------

SCAN20, SCAN200, FIVE, TYPOS = "198.51.100.77", "198.51.100.78", "198.51.100.79", "198.51.100.88"
# The lab server cannot use nftables or the journal: a later file switches
# every jail to the lab action and to log files, and points recidive at the
# server's own log (it sets no key auto_sec sets).
SLOW_ZZ = ("[DEFAULT]\nbanaction = lab\nbanaction_allports = lab\nbackend = polling\nignoreself = false\n"
           "[sshd]\nbackend = polling\nlogpath = {r}/auth.log\n[recidive]\nlogpath = {r}/f2b.log\n")
PURGE_ONCE = ("import sys; sys.path.insert(0, sys.argv[1]); from fail2ban.server.database import Fail2BanDb; "
              "db = Fail2BanDb(sys.argv[2]); db.purgeage = sys.argv[3]; db.purge()")


def auth_line(when, ip, user="root", n=0, accepted=False):
    stamp = time.strftime("%b %e %H:%M:%S", time.localtime(when))
    if accepted:
        return "%s lab sshd[%d]: Accepted password for %s from %s port %d ssh2\n" % (stamp, 2000 + n, user, ip, 5000 + n)
    return "%s lab sshd[%d]: Failed password for %s from %s port %d ssh2\n" % (stamp, 1000 + n, user, ip, 4000 + n)


def slow_auth_log(lab, now):
    """fixtures/slow-scanner.auth.txt as sshd log lines, oldest first."""
    rows = []
    for n, ln in enumerate(read(os.path.join(lab.a.fixtures, "slow-scanner.auth.txt")).splitlines()):
        parts = ln.split()
        if len(parts) == 4 and parts[0].isdigit():
            when = now - int(parts[0]) * 60
            rows.append((when, n, auth_line(when, parts[1], parts[2], n, parts[3] == "accepted")))
    return "".join(r[2] for r in sorted(rows))


def fails_now(s, ip, n):
    now = time.time()
    with open(os.path.join(s.r, "auth.log"), "a", encoding="utf-8") as f:
        for i in range(n):
            f.write(auth_line(now, ip, n=500 + i))


def wait_for(fn, timeout=20, step=0.5):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(step)
    return bool(fn())


def age_ban(s, jail, ip, days):
    """Make a ban look `days` old in the server's database (the server is stopped)."""
    db = sqlite3.connect(os.path.join(s.r, "f2b.sqlite3"))
    old = int(time.time()) - int(days * 86400)
    for tbl in ("bans", "bips"):
        db.execute("UPDATE %s SET timeofban=? WHERE ip=? AND jail=?" % tbl, (old, ip, jail))
    db.commit()
    db.close()


def slow_server(lab, d):
    tag = "S22"
    # auto_sec's own main file gives the sshd jail auto_sec's defaults: 4 in 10m,
    # bantime 1h, bantime.increment with factor 2 and no bantime.maxtime.
    t = lab.tree(d, {"jail.d/" + OWN: read(lab.cand["default"])}, "s22")
    s = Server(lab, d, t, "s22-" + d, dbpurgeage=None)
    write(os.path.join(t, "jail.d/zz-lab.local"), SLOW_ZZ.format(r=s.r))
    write(os.path.join(s.r, "auth.log"), slow_auth_log(lab, time.time()))
    if not s.start():
        return
    try:
        time.sleep(3)
        expect(d, tag + " one failed login every 20 minutes (and slower): the sshd jail (4 in 10m) bans nobody",
               (s.jails(), s.banned("sshd")), (["sshd"], []))
        s.cli("set", "sshd", "banip", "203.0.113.5")
        time.sleep(1)
        pid, sshd_before = s.pid(), [s.get("sshd", k) for k in ("maxretry", "findtime", "bantime")]
        s.actions(clear=True)
        write(os.path.join(t, SLOW_REL), read(lab.cand["slow"]))
        write(os.path.join(t, DB_REL), read(lab.cand["slow-db"]).replace("@AUTOSEC_DBPURGEAGE@", "2592000"))
        rc_t = s.cli("-t")[0]
        rc = s.cli("reload")[0]
        wait_for(lambda: s.banned("sshd-slow") == [SCAN20, SCAN200])
        time.sleep(2)
        expect(d, tag + " with auto_sec's two files, after a reload: sshd-slow bans the scanner (6 in 100 minutes) "
                    "and one ten times slower (6 in 1000 minutes); 5 in 20 hours and a person's 2 typos are not banned",
               (rc_t, rc, s.jails(), s.banned("sshd-slow"), s.banned("recidive")),
               (0, 0, ["recidive", "sshd", "sshd-slow"], [SCAN20, SCAN200], []))
        acts = s.actions(clear=True)
        expect(d, tag + " the reload: same PID, the sshd jail keeps its ban and its values, no action ran for it",
               (s.pid() == pid, s.banned("sshd"), [s.get("sshd", k) for k in ("maxretry", "findtime", "bantime")],
                [a for a in acts if " sshd " in a]), (True, ["203.0.113.5"], sshd_before, []))
        expect(d, tag + " the new jails run with the planned values, and dbpurgeage is 30d",
               ([s.get("sshd-slow", k) for k in ("maxretry", "findtime", "bantime")],
                [s.get("recidive", k) for k in ("maxretry", "findtime", "bantime")], s.dbpurgeage()),
               (["6", "86400", "604800"], ["3", "604800", "2419200"], 2592000))

        # the role's proof after a reload: the helper's --snapshot and --verify --before, also when it must fail
        snap = os.path.join(s.r, "snapshot.json")

        def proof(*args, client=None):
            rc, out, err = run([sys.executable, "-I", lab.a.helper, "--conf", t, "--client", client or lab.client(d)] + list(args))
            return rc, (json.loads(out) if rc == 0 and out.startswith("{") else {}), err
        s.cli("set", "sshd", "banip", "203.0.113.9")
        wait_for(lambda: "203.0.113.9" in (s.banned("sshd") or []), timeout=10)
        rc, sn, err = proof("--snapshot", snap)
        expect(d, tag + " the helper's snapshot: the jails, the PID and counts on stdout; the file is 0600",
               (rc, sn.get("ok"), sn.get("jails"), str(sn.get("pid")) == pid, sn.get("banned"),
                stat.S_IMODE(os.stat(snap).st_mode) if os.path.exists(snap) else None),
               (0, True, ["recidive", "sshd", "sshd-slow"], True, {"recidive": 0, "sshd": 2, "sshd-slow": 2}, 0o600))
        check(d, tag + " ... and no address leaves the host", "203.0.113." not in json.dumps(sn) and SCAN20 not in json.dumps(sn), sn)
        rc, v, err = proof("--verify", "--before", snap, "--expect-jail", "sshd-slow", "--expect-jail", "recidive")
        expect(d, tag + " verify against the snapshot when nothing happened: no ban lost, same PID, the jails run",
               (rc, v.get("bans_lost"), (v.get("pid") or {}).get("same"), v.get("expected_missing")), (0, [], True, []))
        s.cli("set", "sshd", "unbanip", "203.0.113.9")
        wait_for(lambda: "203.0.113.9" not in (s.banned("sshd") or []), timeout=10)
        rc, v, err = proof("--verify", "--before", snap, "--expect-jail", "nosuch")
        expect(d, tag + " a ban that is gone and a jail that does not run are both reported",
               (rc, v.get("bans_lost"), v.get("expected_missing")),
               (0, [{"addresses": ["203.0.113.9"], "jail": "sshd"}], ["nosuch"]))
        rc, v, err = proof("--verify", "--before", snap, "--released-jail", "sshd")
        expect(d, tag + " ... but not for a jail the run removes on purpose", (rc, v.get("bans_lost")), (0, []))
        s.cli("set", "recidive", "bantime", "8")
        s.cli("set", "recidive", "banip", "203.0.113.10")
        wait_for(lambda: s.banned("recidive") == ["203.0.113.10"], timeout=5, step=0.2)
        rc, sn2, err = proof("--snapshot", snap + ".2")
        wait_for(lambda: s.banned("recidive") == [], timeout=30)
        rc2, v, err = proof("--verify", "--before", snap + ".2")
        s.cli("set", "recidive", "bantime", "2419200")
        expect(d, tag + " a ban that ran out since the snapshot is not a lost ban",
               (rc, (sn2.get("banned") or {}).get("recidive"), rc2, v.get("bans_lost"), s.banned("recidive")), (0, 1, 0, [], []))
        garble = os.path.join(s.r, "f2bc-garble")
        write(garble, "#!/bin/sh\ncase \"$*\" in\n  *\"banip --with-time\") echo 'another format'; exit 0 ;;\nesac\n"
                      "exec %s \"$@\"\n" % lab.client(d), 0o755)
        rc, sn3, err = proof("--snapshot", snap + ".3", client=garble)
        check(d, tag + " a ban list the helper cannot read: no snapshot, and it says why (the role then stops before the reload)",
              rc == 2 and "cannot read the bans of recidive, sshd, sshd-slow" in err and not os.path.exists(snap + ".3"),
              (rc, err[-300:]))

        # recidive: three bans by the sshd jail inside its window
        seen = []
        for n in range(3):
            s.cli("set", "sshd", "banip", "198.51.100.91")
            wait_for(lambda: n == 2 and s.banned("recidive") == ["198.51.100.91"], timeout=4)
            seen.append(s.banned("recidive"))
            s.cli("set", "sshd", "unbanip", "198.51.100.91")
            time.sleep(1)
        expect(d, tag + " recidive: three bans of one address by the sshd jail; it bans on the third, not before",
               seen, [[], [], ["198.51.100.91"]])
        # the same by failed logins: the slow jail's ban counts too
        fails_now(s, "198.51.100.92", 4)
        wait_for(lambda: "198.51.100.92" in (s.banned("sshd") or []))
        first = (s.banned("sshd"), s.banned("sshd-slow"), s.banned("recidive"))
        s.cli("set", "sshd", "unbanip", "198.51.100.92")
        time.sleep(1)
        fails_now(s, "198.51.100.92", 4)
        wait_for(lambda: "198.51.100.92" in (s.banned("recidive") or []))
        check(d, tag + " an address the sshd jail bans twice in a day has 8 failures: sshd-slow bans it too, "
                   "and that is the third ban recidive sees",
              "198.51.100.92" in first[0] and "198.51.100.92" not in first[1] and "198.51.100.92" not in first[2]
              and "198.51.100.92" in s.banned("sshd-slow") and "198.51.100.92" in s.banned("recidive"),
              (first, s.banned("sshd"), s.banned("sshd-slow"), s.banned("recidive")))

        # growth: sshd-slow has no growth settings of its own; it takes [DEFAULT]'s
        expect(d, tag + " first ban by sshd-slow: 1w", s.ban_time("sshd-slow", SCAN20), 604800)
        s.stop()
        age_ban(s, "sshd-slow", SCAN20, 8)
        if not s.start():
            return
        time.sleep(3)
        rc, v, err = proof("--verify", "--before", snap)
        expect(d, tag + " after a restart the proof says so: another PID", (rc, (v.get("pid") or {}).get("same")), (0, False))
        gone = SCAN20 not in (s.banned("sshd-slow") or [])
        fails_now(s, SCAN20, 6)
        wait_for(lambda: s.ban_time("sshd-slow", SCAN20) == 2419200)
        expect(d, tag + " the 1w ban is over (8 days old); the scanner comes back: sshd-slow bans it for 4w, "
                    "as [DEFAULT] bantime.increment with factor 2 says (1w x 2 x 2)",
               (gone, s.ban_time("sshd-slow", SCAN20)), (True, 2419200))
        check(d, tag + " fail2ban's log says so", "[sshd-slow] Increase Ban " + SCAN20 in s.log(), s.log()[-600:])

        # a ban until you unban (-1), a reload, fail2ban's own purge, a restart
        write(os.path.join(t, SLOW_REL), read(lab.cand["slow-perm"]))
        rc = s.cli("reload")[0]
        time.sleep(2)
        s.cli("set", "sshd-slow", "banip", "192.0.2.66")
        time.sleep(1)
        rc2 = s.cli("reload")[0]
        time.sleep(2)
        expect(d, tag + " bantime -1: loaded by a reload; a ban is there after another reload; older bans stay",
               (rc, rc2, s.get("sshd-slow", "bantime"), s.get("recidive", "bantime"), s.ban_time("sshd-slow", "192.0.2.66"),
                SCAN200 in s.banned("sshd-slow"), "198.51.100.91" in s.banned("recidive")),
               (0, 0, "-1", "-1", -1, True, True))
        s.stop()
        age_ban(s, "sshd-slow", "192.0.2.66", 400)
        age_ban(s, "recidive", "198.51.100.91", 3)
        rc = run([sys.executable, "-I", "-B", "-c", PURGE_ONCE, lab.pypath(d), os.path.join(s.r, "f2b.sqlite3"), "1d"])[0]
        if not s.start():
            return
        time.sleep(3)
        expect(d, tag + " after fail2ban's own purge with dbpurgeage 1d and a restart: the 400-day-old permanent ban "
                    "and the 3-day-old 4w ban are both back",
               (rc, "192.0.2.66" in s.banned("sshd-slow"), "198.51.100.91" in s.banned("recidive")), (0, True, True))
        rc, out, err = s.cli("unban", "192.0.2.66")
        time.sleep(1)
        expect(d, tag + " fail2ban-client unban lifts the permanent ban",
               (rc, "192.0.2.66" in s.banned("sshd-slow")), (0, False))
    finally:
        s.stop()


# --- S23: role 03's slow-scanner task files, run by ansible-playbook -------------------

def slow_ansible(lab, d, playbook_bin, jobs=1):
    ptag = os.path.basename(os.path.dirname(os.path.dirname(playbook_bin)))
    tag = "S23 " + ptag
    os.makedirs(os.path.join(lab.w, ptag), exist_ok=True)
    stubs = os.path.join(lab.w, "stubs")
    write(os.path.join(stubs, "dpkg-query"),
          "#!/bin/sh\n# lab stub: fail2ban 1.0.2 is installed\ncase \"$*\" in\n"
          "  *Version*) printf 'ii  1.0.2-3ubuntu0.1' ;;\n  *) printf 'ii ' ;;\nesac\n", 0o755)
    write(os.path.join(stubs, "systemctl"),
          "#!/bin/sh\n# lab stub: fail2ban.service active and enabled\ncase \"$1\" in\n"
          "  is-active) echo active ;;\n  is-enabled) echo enabled ;;\n  *) exit 1 ;;\nesac\n", 0o755)
    # The same, without fail2ban: dpkg-query knows no such package.
    stubs_none = os.path.join(lab.w, "stubs-none")
    write(os.path.join(stubs_none, "dpkg-query"),
          "#!/bin/sh\n# lab stub: fail2ban is not installed\n"
          "echo 'dpkg-query: no packages found matching fail2ban' >&2\nexit 1\n", 0o755)
    write(os.path.join(stubs_none, "systemctl"),
          "#!/bin/sh\n# lab stub: no fail2ban.service\ncase \"$1\" in\n"
          "  is-active) echo inactive; exit 3 ;;\n  is-enabled) echo not-found; exit 4 ;;\n  *) exit 1 ;;\nesac\n", 0o755)
    canary = read(os.path.join(lab.a.fixtures, "canary.jail.local")).replace("/var/log/", "@LOGS@/")
    real = lab.client(d)
    fail_reload = os.path.join(lab.w, ptag, "f2bc-slow-fail-reload")
    flag = fail_reload + ".done"
    if os.path.exists(flag):
        os.unlink(flag)
    write(fail_reload, """#!/bin/sh
case "$*" in
  *" reload") if [ ! -e %s ]; then : > %s; echo 'ERROR   injected reload failure' >&2; exit 255; fi ;;
esac
exec %s "$@"
""" % (flag, flag, real), 0o755)
    alt_action = {"action.d/alt-allports.conf": "[Definition]\nactionstart =\nactionstop =\nactioncheck =\n"
                                               "actionban =\nactionunban =\n"}

    def state(s, t, jails=("sshd", "sshd-slow", "recidive")):
        running = s.jails() or []
        return {"pid": s.pid(), "jails": running, "banned": {j: s.banned(j) for j in jails if j in running},
                "values": {j: [s.get(j, k) for k in ("maxretry", "findtime", "bantime")] for j in running},
                "dbpurgeage": s.dbpurgeage(),
                "files": {rel: (read(os.path.join(t, rel)) if os.path.exists(os.path.join(t, rel)) else None)
                          for rel in (SLOW_REL, DB_REL, "jail.d/" + OWN, "jail.local", "fail2ban.local")}}

    def case(name, files=None, ev=None, keep=None, auth=False, check_mode=False, stub=None, start=True,
             dbpurgeage=None, zz=SLOW_ZZ, before_run=None, bans=(("sshd", "203.0.113.5"),), nodb=False):
        """One ansible-playbook run of ansible-lab.yml against a lab server.
        keep=(tree, server name): run again on the same tree, database and logs.
        auth: the sshd log holds fixtures/slow-scanner.auth.txt before the server starts.
        before_run(server): called when the server runs, right before the playbook.
        nodb: the server runs without its database (dbfile = None)."""
        name = ptag + "-" + name
        t = keep[0] if keep else lab.tree(d, files or {}, "s23-" + name)
        s = Server(lab, d, t, keep[1] if keep else "s23-" + name, fresh=not keep, dbpurgeage=dbpurgeage)
        if nodb:
            p = os.path.join(t, "fail2ban.local")
            write(p, re.sub(r"(?m)^dbfile = .*$", "dbfile = None", read(p)))
        if not keep:
            write(os.path.join(t, "jail.d/zz-lab.local"), zz.format(r=s.r))
            if auth:
                write(os.path.join(s.r, "auth.log"), slow_auth_log(lab, time.time()))
        if start:
            if not s.start():
                return None
            time.sleep(2 if auth else 0.5)
            for jail, ip in bans:
                s.cli("set", jail, "banip", ip)
            wait_for(lambda: all(ip in (s.banned(jail) or []) for jail, ip in bans), timeout=10)
            time.sleep(0.5)
            if before_run:
                before_run(s)
        env = dict(os.environ, LC_ALL="C.UTF-8", ANSIBLE_NOCOLOR="1", ANSIBLE_RETRY_FILES_ENABLED="False",
                   ANSIBLE_LOCALHOST_WARNING="False", ANSIBLE_INVENTORY_UNPARSED_WARNING="False",
                   ANSIBLE_ROLES_PATH=lab.a.roles, PATH=(stub or stubs) + ":" + os.environ.get("PATH", ""))
        plan_out = os.path.join(lab.w, ptag, "plan-%s.json" % name)
        if os.path.exists(plan_out):
            os.unlink(plan_out)
        run_dir = os.path.join(lab.w, ptag, "run-" + name)
        v = {"_f2b_conf_dir": t, "_f2b_client": lab.client(d), "_f2b_conffiles_file": lab.conffiles(d),
             "_f2b_python": sys.executable, "_f2b_file_owner": os.environ.get("USER") or str(os.getuid()),
             "_f2b_run_dir": run_dir, "_f2b_sim_dir": run_dir + "/f2b-sim", "_f2b_prev_dir": run_dir + "/f2b-prev",
             "_f2b_backup_dir": os.path.join(lab.w, ptag, "backup-" + name), "ssh_port": 22,
             "fail2ban_slow_scanners": True, "lab_plan_out": plan_out}
        v.update(ev or {})
        evf = os.path.join(lab.w, ptag, "ev-%s.json" % name)
        write(evf, json.dumps(v).replace("@TREE@", t).replace("@CLIENT@", lab.client(d)))
        before = state(s, t) if start else None
        log_at = len(s.log()) if start else 0
        argv = [playbook_bin, os.path.join(lab.a.here, "ansible-lab.yml"), "-e", "@" + evf]
        if check_mode:
            argv.append("--check")
        if start:
            s.actions(clear=True)
        rc, out, err = run(argv, env=env, cwd=lab.w)
        if auth and start and rc == 0 and not check_mode:
            wait_for(lambda: s.banned("sshd-slow") == [SCAN20, SCAN200], timeout=15)
        res = {"rc": rc, "out": out + err, "srv": s, "t": t, "name": "s23-" + name, "before": before,
               "plan": json.loads(read(plan_out)) if os.path.exists(plan_out) else None}
        if start:
            res["after"] = state(s, t)
            res["newlog"] = s.log()[log_at:]
            res["actions"] = s.actions()
        else:
            res["after"] = {"files": {rel: (read(os.path.join(t, rel)) if os.path.exists(os.path.join(t, rel)) else None)
                                      for rel in (SLOW_REL, DB_REL)}}
        write(os.path.join(lab.w, "s23-%s.log" % name), out + err)
        return res

    def done(r):
        if r and r.get("srv"):
            r["srv"].stop()

    def recap(out):
        m = re.search(r"localhost\s*:\s*ok=\d+\s+changed=(\d+)\s+unreachable=\d+\s+failed=(\d+)", out)
        return (int(m.group(1)), int(m.group(2))) if m else None

    def nothing_written(r):
        return (r["after"]["files"][SLOW_REL], r["after"]["files"][DB_REL])

    def k1():
        # hardening keep: only the slow-scanner part runs
        r = case("stock", auth=True, ev={"_ssh_controller_ip": "192.0.2.200"})
        if not r:
            return
        a, b = r["after"], r["before"]
        expect(d, tag + " k1 stock, fail2ban_hardening_enabled keep: run ok, auto_sec's two files written, no other file",
               (r["rc"], (a["files"][SLOW_REL] or "").startswith(MARKER), (a["files"][DB_REL] or "").startswith(MARKER),
                a["files"]["jail.d/" + OWN], a["files"]["jail.local"], a["files"]["fail2ban.local"] == b["files"]["fail2ban.local"]),
               (0, True, True, None, None, True))
        expect(d, tag + " k1 before the run the sshd jail had not banned the slow scanner; after it sshd-slow has, "
                    "with the one ten times slower; nobody else",
               (b["banned"], a["banned"]),
               ({"sshd": ["203.0.113.5"]}, {"sshd": ["203.0.113.5"], "sshd-slow": [SCAN20, SCAN200], "recidive": []}))
        expect(d, tag + " k1 one reload, same PID, the sshd jail's values unchanged, no action ran for it",
               (r["newlog"].count("Reload finished"), a["pid"] == b["pid"], a["values"]["sshd"],
                [x for x in r["actions"] if " sshd " in x]), (1, True, b["values"]["sshd"], []))
        expect(d, tag + " k1 the new jails run with the planned values; dbpurgeage set to 30d without a restart",
               (a["values"].get("sshd-slow"), a["values"].get("recidive"), b["dbpurgeage"], a["dbpurgeage"]),
               (["6", "86400", "604800"], ["3", "604800", "2419200"], 86400, 2592000))
        check(d, tag + " k1 the role's own proof passed", "fail2ban slow S7: verified" in r["out"], r["out"][-600:])
        p = r["plan"] or {"plan": [], "line": ""}
        expect(d, tag + " k1 plan: two files, the runtime dbpurgeage, the reload",
               [(i["do"], i["what"].split(":")[0].replace(r["t"], "")) for i in p["plan"]],
               [("write", "/" + SLOW_REL), ("write", "/" + DB_REL),
                ("reload", "fail2ban dbpurgeage at run time (fail2ban-client set dbpurgeage; no restart)"),
                ("reload", "fail2ban, for 00-autosec-slow.conf (the other jails and every ban stay)")])
        check(d, tag + " k1 plan: your values in the item, what fail2ban will run in its note",
              p["plan"] and "sshd-slow bans after 6 failed logins in 1d for 1w (port 22); recidive bans after 3 bans by the "
              "other jails in 1w for 4w (all ports; sshd-slow alone cannot reach it" in p["plan"][0]["what"]
              and "ignoreip: both jails take the list in [DEFAULT], and no address of yours is named" in p["plan"][0]["what"]
              and "[DEFAULT]" not in "\n".join(ln for ln in (a["files"][SLOW_REL] or "").splitlines() if not ln.startswith("#"))
              and "sshd-slow as fail2ban will run it: 6 in 1d, banned for 1w" in p["plan"][0]["note"]
              and "ignoreip nobody" in p["plan"][0]["note"] and "ban action lab (port 22)" in p["plan"][0]["note"]
              and "dbpurgeage at least 30d" in p["plan"][1]["what"]
              and "dbpurgeage 2592000 seconds: the largest value is fail2ban_slow_dbpurgeage 30d; the server has 1d now"
              in p["plan"][1]["note"], p["plan"])
        expect(d, tag + " k1 plan line", p["line"],
               "keep (no install, no file, no reload); slow scanners: write 00-autosec-slow.conf and "
               "fail2ban.d/00-autosec.conf; set dbpurgeage, reload fail2ban")
        check(d, tag + " k1 N03-F12: this computer's address is not exempt",
              "WARNING: this computer's address (192.0.2.200) is not in the ignore list of sshd-slow and recidive"
              in r["out"], r["out"][-800:])
        t, name = r["t"], r["name"]
        done(r)
        r2 = case("stock", keep=(t, name), ev={"_ssh_controller_ip": "192.0.2.200"}, bans=())
        if r2:
            expect(d, tag + " k1 second run: nothing changed, no reload, an empty plan, bans kept",
                   (r2["rc"], recap(r2["out"]), "Reload" in r2["newlog"], (r2["plan"] or {}).get("plan"),
                    r2["after"]["banned"].get("sshd-slow"), r2["after"]["dbpurgeage"]),
                   (0, (0, 0), False, [], [SCAN20, SCAN200], 2592000))
            expect(d, tag + " k1 second run: plan line", (r2["plan"] or {}).get("line"),
                   "keep (no install, no file, no reload); slow scanners: no file changes; no effective change, no reload")
            done(r2)
        r4 = case("stock", keep=(t, name), ev={"fail2ban_slow_recidive_enabled": False}, bans=(("recidive", "198.51.100.7"),))
        if r4:
            a4, b4 = r4["after"], r4["before"]
            expect(d, tag + " k1 fail2ban_slow_recidive_enabled: false later: auto_sec's own recidive jail goes by one reload "
                        "(its ban with it), sshd-slow keeps its bans, same PID",
                   (r4["rc"], b4["banned"].get("recidive"), a4["jails"], a4["banned"].get("sshd-slow"),
                    r4["newlog"].count("Reload finished"), a4["pid"] == b4["pid"], "[recidive]" in (a4["files"][SLOW_REL] or "")),
                   (0, ["198.51.100.7"], ["sshd", "sshd-slow"], [SCAN20, SCAN200], 1, True, False))
            check(d, tag + " k1 ... N03-F9 and the plan say that its bans are released",
                  "fail2ban_slow_recidive_enabled is false. auto_sec added that jail in an earlier run" in r4["out"]
                  and "the addresses it bans now are released" in r4["out"]
                  and "auto_sec's recidive jail of an earlier run goes, its bans are lifted" in (r4["plan"] or {"plan": [{"what": ""}]})["plan"][-1]["what"],
                  (r4["plan"], r4["out"][-800:]))
            done(r4)
        r3 = case("stock", keep=(t, name), ev={"fail2ban_slow_scanners": False}, bans=())
        if r3:
            expect(d, tag + " k1 the switch back to false: nothing changed, the files and jails stay, the plan is as without it",
                   (r3["rc"], recap(r3["out"]), "Reload" in r3["newlog"], r3["after"]["files"] == r3["before"]["files"],
                    r3["after"]["jails"], (r3["plan"] or {}).get("plan"), (r3["plan"] or {}).get("line")),
                   (0, (0, 0), False, True, ["sshd", "sshd-slow"], [], "keep (no install, no file, no reload)"))
            check(d, tag + " k1 N03-F8 names the two files and how to remove them",
                  "INFO: auto_sec's %s and %s from an earlier run stay and still apply" % (os.path.join(t, SLOW_REL), os.path.join(t, DB_REL))
                  in r3["out"] and "sudo fail2ban-client -t && sudo fail2ban-client reload" in r3["out"], r3["out"][-800:])
            done(r3)

    def k2():
        r = case("canary", files={"jail.local": canary}, bans=(("sshd", "203.0.113.5"), ("recidive", "198.51.100.7")),
                 ev={"office_static_ip": "203.0.113.7"})
        if not r:
            return
        a, b = r["after"], r["before"]
        srv = r["srv"]
        expect(d, tag + " k2 canary (its own recidive): run ok, jail.local untouched, only sshd-slow is new, both bans kept, "
                    "same PID, one reload",
               (r["rc"], a["files"]["jail.local"] == b["files"]["jail.local"], sorted(set(a["jails"]) - set(b["jails"])),
                a["banned"]["sshd"], a["banned"]["recidive"], a["pid"] == b["pid"], r["newlog"].count("Reload finished")),
               (0, True, ["sshd-slow"], ["203.0.113.5"], ["198.51.100.7"], True, 1))
        expect(d, tag + " k2 every jail of the canary keeps its values; no action ran for them",
               ({j: a["values"][j] for j in b["jails"]}, [x for x in r["actions"] if " sshd-slow " not in x]),
               (b["values"], []))
        check(d, tag + " k2 auto_sec's file has no recidive section, and N03-F9 says why",
              "[recidive]" not in (a["files"][SLOW_REL] or "[recidive]")
              and "NOTE: auto_sec adds no recidive jail on localhost: you have one of your own (jail.local)" in r["out"],
              r["out"][-800:])
        expect(d, tag + " k2 dbpurgeage follows the canary's bantime.maxtime 8w",
               (b["dbpurgeage"], a["dbpurgeage"], "dbpurgeage = 4838400\n" in (a["files"][DB_REL] or "")), (86400, 4838400, True))
        got = srv.cli("get", "sshd-slow", "ignoreip")[1]
        check(d, tag + " k2 sshd-slow ignores the canary's own addresses and office_static_ip",
              all(x in got for x in ("198.51.100.1", "203.0.113.2", "203.0.113.7")), got)
        p = r["plan"] or {"plan": []}
        check(d, tag + " k2 plan: no recidive in the item; the note says it is left out and why 8w",
              p["plan"] and "recidive bans" not in p["plan"][0]["what"] and "plus 203.0.113.7" in p["plan"][0]["what"]
              and "recidive is left out (you have your own)" in p["plan"][0]["note"]
              and "a repeat ban is longer, up to 8w" in p["plan"][0]["note"]
              and "the bantime.maxtime 8w of the jail" in p["plan"][1]["note"], p["plan"])
        done(r)

    def k3():
        r = case("own", files={"jail.local": "[sshd-slow]\nenabled = true\nfilter = sshd\nlogpath = @LOGS@/auth.log\n"})
        if r:
            check(d, tag + " k3 your own [sshd-slow] jail: refused (R03-F9) before anything changed",
                  r["rc"] != 0 and "already has a jail or a section named sshd-slow that auto_sec did not write (in jail.local)"
                  in r["out"] and "Nothing has been changed." in r["out"] and nothing_written(r) == (None, None)
                  and "Reload" not in r["newlog"] and r["after"]["jails"] == r["before"]["jails"], r["out"][-800:])
            done(r)

    def k4():
        theirs = {SLOW_REL: "[sshd-slow]\nmaxretry = 9\n", DB_REL: "[DEFAULT]\ndbpurgeage = 2d\n"}
        r = case("foreign", files=theirs)
        if r:
            check(d, tag + " k4 files with auto_sec's two names that auto_sec did not write: refused (R03-F6), both kept",
                  r["rc"] != 0 and "auto_sec never replaces a file it did not write" in r["out"]
                  and os.path.join(r["t"], SLOW_REL) in r["out"] and os.path.join(r["t"], DB_REL) in r["out"]
                  and nothing_written(r) == (theirs[SLOW_REL], theirs[DB_REL]), r["out"][-800:])
            done(r)

    def k5():
        r = case("noinstall", stub=stubs_none, start=False)
        if r:
            check(d, tag + " k5 fail2ban is not installed and fail2ban_hardening_enabled is keep: refused (R03-F8)",
                  r["rc"] != 0 and "fail2ban_slow_scanners is true, but fail2ban is not installed on localhost" in r["out"]
                  and "this run does not install it" in r["out"] and nothing_written(r) == (None, None), r["out"][-800:])

    def k6():
        ev = {"fail2ban_slow_sshd": {"findtime": "1d", "maxretry": 6, "bantime": -1},
              "fail2ban_slow_recidive": {"findtime": "1w", "maxretry": 3, "bantime": "-1"},
              "fail2ban_slow_recidive_enabled": False}
        r = case("perm", ev=ev)
        if not r:
            return
        srv, a = r["srv"], r["after"]
        expect(d, tag + " k6 bantime -1 and no recidive (sub-switch off): run ok, only sshd-slow, banned until unbanned",
               (r["rc"], a["jails"], a["values"].get("sshd-slow"), "[recidive]" in (a["files"][SLOW_REL] or "")),
               (0, ["sshd", "sshd-slow"], ["6", "86400", "-1"], False))
        check(d, tag + " k6 plan: until you unban, and nothing about recidive",
              r["plan"] and "sshd-slow bans after 6 failed logins in 1d until you unban (port 22); ignoreip: sshd-slow takes "
              "the list in [DEFAULT]" in r["plan"]["plan"][0]["what"], r["plan"])
        srv.cli("set", "sshd-slow", "banip", "192.0.2.66")
        time.sleep(1)
        rc = srv.cli("reload")[0]
        time.sleep(2)
        there, how_long = srv.banned("sshd-slow"), srv.ban_time("sshd-slow", "192.0.2.66")
        rc2 = srv.cli("unban", "192.0.2.66")[0]
        time.sleep(1)
        expect(d, tag + " k6 a permanent ban is there after a reload, and fail2ban-client unban lifts it",
               (rc, there, how_long, rc2, srv.banned("sshd-slow")), (0, ["192.0.2.66"], -1, 0, []))
        done(r)

    def k7():
        r = case("rollback", ev={"_f2b_client": fail_reload})
        if r:
            a, b = r["after"], r["before"]
            check(d, tag + " k7 the reload fails: both files removed again, dbpurgeage and jails as before, the ban kept",
                  r["rc"] != 0 and nothing_written(r) == (None, None) and "Put the previous files back." in r["out"]
                  and "Loaded the previous config again." in r["out"] and a["dbpurgeage"] == b["dbpurgeage"] == 86400
                  and a["jails"] == b["jails"] and a["banned"] == b["banned"] and a["pid"] == b["pid"],
                  (a["dbpurgeage"], a["jails"], a["banned"], r["out"][-800:]))
            done(r)

    def k8():
        ev = {"fail2ban_hardening_enabled": True, "office_static_ip": "203.0.113.7"}
        r = case("both", ev=ev)
        if not r:
            return
        a, b = r["after"], r["before"]
        expect(d, tag + " k8 fail2ban_hardening_enabled true and slow scanners in one run: three files, two reloads, "
                    "ban and PID kept",
               (r["rc"], [(a["files"][x] or "").startswith(MARKER) for x in ("jail.d/" + OWN, SLOW_REL, DB_REL)],
                r["newlog"].count("Reload finished"), a["banned"]["sshd"], a["pid"] == b["pid"], a["jails"]),
               (0, [True, True, True], 2, ["203.0.113.5"], True, ["recidive", "sshd", "sshd-slow"]))
        expect(d, tag + " k8 N03-F11 in that same run, once: the plan saw no growing bans yet, the step after the main file does",
               r["out"].count("is on and no bantime.maxtime is set for recidive, sshd, sshd-slow"), 1)
        t, name = r["t"], r["name"]
        done(r)
        r2 = case("both", keep=(t, name), ev=ev, bans=())
        if r2:
            expect(d, tag + " k8 second run: the main file's [DEFAULT] values in auto_sec's own slow jails are no leak; "
                        "nothing changed, no reload",
                   (r2["rc"], recap(r2["out"]), "Reload" in r2["newlog"], "would change jails of yours" in r2["out"]),
                   (0, (0, 0), False, False))
            expect(d, tag + " k8 N03-F11 in the second run: by the preflight, and not again",
                   r2["out"].count("is on and no bantime.maxtime is set for recidive, sshd, sshd-slow"), 1)
            done(r2)

    def k9():
        # another firewall tool for the all-ports ban, and a dbpurgeage of the operator's own
        zz = SLOW_ZZ.replace("banaction_allports = lab", "banaction_allports = alt-allports")
        r = case("recout", files=alt_action, zz=zz, dbpurgeage="12h")
        if r:
            a, b = r["after"], r["before"]
            expect(d, tag + " k9 the all-ports action is another tool: run ok, only sshd-slow is added",
                   (r["rc"], a["jails"], "[recidive]" in (a["files"][SLOW_REL] or "")), (0, ["sshd", "sshd-slow"], False))
            check(d, tag + " k9 N03-F9 names the fix (banaction_allports)",
                  "its ban on all ports would use another firewall tool than the sshd jail (recidive: alt; sshd: lab)"
                  in r["out"] and "Set banaction_allports in [DEFAULT]" in r["out"], r["out"][-800:])
            expect(d, tag + " k9 your fail2ban.local says dbpurgeage 12h: it wins, the running value stays",
                   (b["dbpurgeage"], a["dbpurgeage"], "dbpurgeage = 2592000\n" in (a["files"][DB_REL] or "")), (43200, 43200, True))
            check(d, tag + " k9 N03-F10 says so, and the plan lists no runtime change of dbpurgeage",
                  "fail2ban.local on localhost sets dbpurgeage, and it wins over auto_sec's file" in r["out"]
                  and [i["do"] for i in r["plan"]["plan"]] == ["write", "write", "reload"], (r["plan"], r["out"][-800:]))
            done(r)

    def k10():
        r = case("drift", before_run=lambda s: s.cli("set", "dbpurgeage", "5d"))
        if r:
            check(d, tag + " k10 dbpurgeage set by hand in the running server (not in its files): refused (R03-F7)",
                  r["rc"] != 0 and "is running a different config than its files" in r["out"]
                  and "dbpurgeage running 432000 s, files 86400 s" in r["out"] and nothing_written(r) == (None, None)
                  and r["after"]["dbpurgeage"] == 432000, r["out"][-800:])
            done(r)

    def k11():
        r = case("check", check_mode=True)
        if r:
            check(d, tag + " k11 --check: rc 0, nothing written, no reload, dbpurgeage untouched",
                  r["rc"] == 0 and nothing_written(r) == (None, None) and "Reload" not in r["newlog"]
                  and r["after"]["dbpurgeage"] == 86400 and "Check mode: write 00-autosec-slow.conf" in r["out"],
                  r["out"][-800:])
            done(r)

    def k12():
        r = case("early", files={"jail.d/0-early.conf": "[DEFAULT]\nignoreip = 192.0.2.9\n"},
                 ev={"office_static_ip": "203.0.113.7"})
        if r:
            check(d, tag + " k12 an ignoreip in a file read before auto_sec's: refused (R03-F5), nothing written",
                  r["rc"] != 0 and "jail.d/0-early.conf sets ignoreip = 192.0.2.9 in [DEFAULT]" in r["out"]
                  and "its empty ignoreip in [DEFAULT] would cancel yours for every jail" in r["out"]
                  and nothing_written(r) == (None, None), r["out"][-800:])
            done(r)

    def k13():
        r = case("stopped", start=False)
        if r:
            check(d, tag + " k13 fail2ban is installed but does not run: the files are written, nothing is loaded, N03-F13 says so",
                  r["rc"] == 0 and (r["after"]["files"][SLOW_REL] or "").startswith(MARKER)
                  and (r["after"]["files"][DB_REL] or "").startswith(MARKER)
                  and "does not answer (it is not running). auto_sec writes its files; they load when fail2ban starts" in r["out"]
                  and [i["do"] for i in r["plan"]["plan"]] == ["write", "write"]
                  and r["plan"]["line"].endswith("fail2ban is not running: the files load when it starts"),
                  (r["plan"], r["out"][-800:]))

    def k14():
        # PF1: the shapes of the values, before anything is read on the host
        r = case("shape", start=False, ev={
            "fail2ban_slow_sshd": {"findtime": "1d", "maxretry": 6},
            "fail2ban_slow_recidive": {"findtime": "1 week", "maxretry": 0, "bantime": "1w\nignoreip = 0.0.0.0/0"}})
        if r:
            check(d, tag + " k14 a missing key, a time with a space, maxretry 0 and a value with a newline: all refused together (PF1)",
                  r["rc"] != 0 and "fail2ban_slow_sshd has the keys findtime, maxretry" in r["out"]
                  and "fail2ban_slow_recidive.bantime is 1w" in r["out"] and "fail2ban_slow_recidive.findtime is 1 week" in r["out"]
                  and "fail2ban_slow_recidive.maxretry is 0" in r["out"] and "Nothing has been changed." in r["out"]
                  and nothing_written(r) == (None, None), r["out"][-900:])
        r = case("shape2", start=False, ev={"fail2ban_slow_dbpurgeage": "-1"})
        if r:
            check(d, tag + " k14 fail2ban_slow_dbpurgeage -1: refused (PF1)",
                  r["rc"] != 0 and "fail2ban_slow_dbpurgeage (-1) must be a time like 30d or 8w" in r["out"]
                  and nothing_written(r) == (None, None), r["out"][-900:])
        r = case("shape3", start=False, ev={"fail2ban_slow_scanners": "maybe"})
        if r:
            check(d, tag + " k14 fail2ban_slow_scanners maybe: refused (PF1)",
                  r["rc"] != 0 and "fail2ban_slow_scanners (maybe) and" in r["out"] and "must be true or false" in r["out"]
                  and nothing_written(r) == (None, None), r["out"][-900:])

    def k15():
        r = case("nodb", nodb=True)
        if r:
            a = r["after"]
            check(d, tag + " k15 fail2ban without its database (dbfile = None): the jails are added, nothing is set at run time, "
                       "N03-F10 says that the longer memory has no effect",
                  r["rc"] == 0 and a["jails"] == ["recidive", "sshd", "sshd-slow"] and a["dbpurgeage"] is None
                  and "fail2ban's database is off on localhost (dbfile = None)" in r["out"]
                  and [i["do"] for i in r["plan"]["plan"]] == ["write", "write", "reload"]
                  and a["banned"]["sshd"] == ["203.0.113.5"] and a["pid"] == r["before"]["pid"], (a, r["out"][-800:]))
            done(r)

    def k16():
        # After the plan, a recidive jail of the operator's own appears (and is loaded).
        r = case("midrun", ev={"lab_between": [
            "sh", "-c", "printf '[recidive]\\nenabled = true\\n' > @TREE@/jail.d/zz-own.local && @CLIENT@ -c @TREE@ reload"]})
        if r:
            check(d, tag + " k16 a recidive jail of yours appears between the plan and the write: stopped (M03-F1), nothing written",
                  r["rc"] != 0 and "changed during this run: the plan had a recidive jail from auto_sec" in r["out"]
                  and "now the trial says to leave it out" in r["out"] and nothing_written(r) == (None, None)
                  and r["after"]["jails"] == ["recidive", "sshd"], (r["after"]["jails"], r["out"][-800:]))
            done(r)

    def k17():
        # An ignore list only in the operator's [sshd] section.
        own = {"jail.local": "[sshd]\nignoreip = 10.9.9.9\n"}
        r = case("ownign", files=own)
        if r:
            check(d, tag + " k17 an ignoreip only in your [sshd] section and no address named: refused (R03-F11), nothing written",
                  r["rc"] != 0 and "ignoreip: sshd-slow would not ignore 10.9.9.9" in r["out"]
                  and "put those addresses in fail2ban_ignore_ips" in r["out"] and "Nothing has been changed." in r["out"]
                  and nothing_written(r) == (None, None) and "Reload" not in r["newlog"], r["out"][-900:])
            done(r)
        r = case("ownign2", files=own, ev={"fail2ban_ignore_ips": ["10.9.9.9"]})
        if r:
            got = r["srv"].cli("get", "sshd-slow", "ignoreip")[1]
            check(d, tag + " k17 ... with that address in fail2ban_ignore_ips: run ok, sshd-slow ignores it, the sshd jail is untouched",
                  r["rc"] == 0 and "10.9.9.9" in got and r["after"]["jails"] == ["recidive", "sshd", "sshd-slow"]
                  and r["after"]["values"]["sshd"] == r["before"]["values"]["sshd"]
                  and r["after"]["banned"]["sshd"] == ["203.0.113.5"], (got, r["out"][-800:]))
            done(r)

    def k18():
        # An earlier run added auto_sec's recidive; the operator then enabled one of their own and loaded it.
        mine = {SLOW_REL: read(lab.cand["slow"]),
                DB_REL: read(lab.cand["slow-db"]).replace("@AUTOSEC_DBPURGEAGE@", "2592000"),
                "jail.local": "[recidive]\nenabled = true\nbantime = 2w\n"}
        r = case("takeover", files=mine, bans=(("sshd", "203.0.113.5"), ("recidive", "198.51.100.7")))
        if r:
            a, b = r["after"], r["before"]
            check(d, tag + " k18 a recidive of your own on top of auto_sec's from an earlier run: refused (R03-F10), "
                       "no file, jail or ban changed",
                  r["rc"] != 0 and "would change jails of yours on localhost" in r["out"]
                  and "You now have a recidive jail of your own" in r["out"] and "Nothing has been changed." in r["out"]
                  and a["files"] == b["files"] and "Reload" not in r["newlog"] and a["banned"] == b["banned"]
                  and a["values"] == b["values"] and b["values"]["recidive"] == ["3", "604800", "1209600"],
                  (b["values"], r["out"][-900:]))
            done(r)

    def k19():
        # No fail2ban yet, and this run installs it. The lab cannot install: --check, for the plan.
        r = case("newhost", stub=stubs_none, start=False, check_mode=True, ev={"fail2ban_hardening_enabled": True})
        if r:
            p = r["plan"] or {"plan": [], "line": ""}
            mine = [i for i in p["plan"] if SLOW in i["what"] or "dbpurgeage" in i["what"]]
            expect(d, tag + " k19 no fail2ban yet and fail2ban_hardening_enabled true (--check): the plan lists both files, "
                        "the runtime dbpurgeage and the reload, from your variables alone",
                   (r["rc"], [i["do"] for i in mine], [i["note"] for i in mine], nothing_written(r)),
                   (0, ["write", "write", "reload", "reload"], ["", "", "", ""], (None, None)))
            check(d, tag + " k19 ... the plan line and the check-mode message say that it comes after the install",
                  p["line"].endswith("slow scanners: write 00-autosec-slow.conf and fail2ban.d/00-autosec.conf once fail2ban "
                                     "is installed; set dbpurgeage, reload fail2ban")
                  and "fail2ban is not installed on localhost yet. The real run installs it" in r["out"],
                  (p["line"], r["out"][-800:]))

    def k20():
        # This run's own fail2ban part makes ban times longer than the memory the plan saw. The tree
        # starts with auto_sec's three files as an earlier run with both switches wrote them.
        mine = {"jail.d/" + OWN: read(lab.cand["default"]), SLOW_REL: read(lab.cand["slow"]),
                DB_REL: read(lab.cand["slow-db"]).replace("@AUTOSEC_DBPURGEAGE@", "2592000")}
        more = {"fail2ban_hardening_enabled": True,
                "fail2ban_defaults": {"bantime": "1h", "bantime.increment": True, "bantime.factor": 2,
                                      "bantime.maxtime": "8w", "findtime": "10m", "maxretry": 4}}
        r2 = case("grow", files=mine, ev=more)
        if not r2:
            return
        t, name = r2["t"], r2["name"]
        first = (r2["before"]["jails"], r2["before"]["dbpurgeage"])
        a2, p2 = r2["after"], r2["plan"] or {"plan": []}
        check(d, tag + " k20 a later run gives auto_sec's main file bantime.maxtime 8w: the memory would have to follow, the "
                   "plan did not show that, the step stops (M03-F1) and leaves the slow-scanner files as they were",
              first == (["recidive", "sshd", "sshd-slow"], 2592000) and r2["rc"] != 0
              and "changed during this run: fail2ban.d/00-autosec.conf would now be written (dbpurgeage 4838400 seconds); "
                  "dbpurgeage would now be set in the running fail2ban" in r2["out"]
              and not [i for i in p2["plan"] if "dbpurgeage" in i["what"]]
              and "dbpurgeage = 2592000\n" in (a2["files"][DB_REL] or "") and a2["dbpurgeage"] == 2592000
              and "bantime.maxtime = 8w" in (a2["files"]["jail.d/" + OWN] or ""),
              (first, a2["dbpurgeage"], p2["plan"], r2["out"][-900:]))
        done(r2)
        r3 = case("grow", keep=(t, name), ev=more, bans=())
        if r3:
            a3, p3 = r3["after"], r3["plan"] or {"plan": []}
            expect(d, tag + " k20 the next run: the plan lists the file and the runtime change, and the memory is 8w",
                   (r3["rc"], [i["do"] for i in p3["plan"]], a3["dbpurgeage"], "dbpurgeage = 4838400\n" in (a3["files"][DB_REL] or ""),
                    a3["pid"] == r3["before"]["pid"]),
                   (0, ["write", "reload"], 4838400, True, True))
            done(r3)

    in_parallel(jobs, [(d, f) for f in (k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18,
                                        k19, k20)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--dists", required=True)
    ap.add_argument("--rendered", required=True)
    ap.add_argument("--helper", required=True)
    ap.add_argument("--fixtures", required=True)
    ap.add_argument("--here", required=True)
    ap.add_argument("--roles", required=True)
    ap.add_argument("--server-python", default="")
    ap.add_argument("--server-dist", default="noble")
    ap.add_argument("--slow-server-dists", default="noble resolute",
                    help="builds whose server runs with --server-python, for S22")
    ap.add_argument("--jobs", type=int, default=4, help="checks that run side by side (1: one after the other)")
    ap.add_argument("--ansible", action="append", default=[])
    a = ap.parse_args()
    lab = Lab(a)
    dists = a.dists.split()
    template_checks(lab)

    def build(d):
        config_checks(lab, d)
        slow_config_checks(lab, d)
        code_checks(lab, d)
    in_parallel(a.jobs, [(d, lambda d=d: build(d)) for d in dists])
    if a.server_python and a.server_dist in dists:
        s13_server(lab, a.server_dist)
        s15_drift(lab, a.server_dist)
        in_parallel(a.jobs, [(d, lambda d=d: slow_server(lab, d)) for d in a.slow_server_dists.split() if d in dists])
        in_parallel(a.jobs, [(a.server_dist, lambda pb=pb: s16_ansible(lab, a.server_dist, pb)) for pb in a.ansible])
        for pb in a.ansible:
            slow_ansible(lab, a.server_dist, pb, a.jobs)
    elif a.server_python:
        print("SKIP  server checks: %s is not in --dists" % a.server_dist)
    else:
        print("SKIP  S13 S15 S16 S22 S23: no --server-python (a Python that imports asyncore)")
    print("\n%d passed, %d failed" % (PASSES[0], len(FAILS)))
    for f in FAILS:
        print("  FAILED: " + f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
