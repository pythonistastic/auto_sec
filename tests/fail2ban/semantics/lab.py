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
With --server-python (a Python that imports asyncore; the noble build only):
  S13 reload/restart semantics of a real fail2ban 1.0.2 server
  S15 the helper's drift check and --verify against that server
  S16 role 03's own task files (preflight, trial, decide, apply, report)
      run by ansible-playbook against that server (--ansible, repeatable)

Exit 0 = every check passed, 1 = a check failed, 2 = setup problem.
"""
import argparse
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
import time

FAILS = []
PASSES = [0]
OWN = "00-autosec.conf"
NGINX = "00-autosec-nginx.conf"
MARKER = "# Written by auto_sec (role 03). Do not edit: the next run replaces this file."
CLIENT_CODE = ("import sys; sys.path.insert(0, sys.argv[1]); "
               "from fail2ban.client.fail2banclient import exec_command_line; "
               "exec_command_line(['fail2ban-client'] + sys.argv[2:])")
SERVER_CODE = ("import sys; sys.path.insert(0, sys.argv[1]); "
               "from fail2ban.client.fail2banserver import exec_command_line; "
               "exec_command_line(['fail2ban-server'] + sys.argv[2:])")


def ok(tag, what):
    PASSES[0] += 1
    print("PASS  %-9s %s" % (tag, what))


def bad(tag, what):
    FAILS.append("%s %s" % (tag, what))
    print("FAIL  %-9s %s" % (tag, what))


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
        if not os.path.exists(p):
            write(p, "#!/bin/sh\ncd / || exit 2\nexec %s -I -B -c \"%s\" %s \"$@\"\n"
                  % (sys.executable, CLIENT_CODE, self.pypath(dist)), 0o755)
        return p

    def conffiles(self, dist):
        """dpkg-query -f '${Conffiles}' format, md5 of the unpacked files."""
        p = os.path.join(self.w, "conffiles-" + dist)
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
               running=False, conf_for_running=None):
        work = tree + ".work"
        shutil.rmtree(work, ignore_errors=True)
        cpath = self.cand.get(cand, cand)
        argv = [sys.executable, "-I", self.a.helper, "--conf", tree, "--work", work,
                "--candidate", cpath, "--candidate-name", name, "--ssh-port", str(ssh_port),
                "--client", self.client(dist), "--conffiles", self.conffiles(dist)]
        argv += ["--allowed-jail=" + j for j in jails] + ["--autosec-ip=" + i for i in ips]
        argv += ["--autosec-key=" + k for k in keys]
        if running:
            argv += ["--running", "--runtime-ignore-file", os.path.join(self.w, "no-such-file")]
        rc, out, err = run(argv)
        if rc != 0:
            bad(dist, "helper rc %s: %s" % (rc, err.strip()[-400:]))
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

def config_checks(lab, d):
    canary = read(os.path.join(lab.a.fixtures, "canary.jail.local")).replace("/var/log/", "@LOGS@/")
    canary_jails = ["sshd", "nginx-http-auth", "nginx-botsearch", "nginx-bad-request", "recidive"]
    if not os.path.exists(os.path.join(lab.x(d), "etc/fail2ban/filter.d/nginx-bad-request.conf")):
        # fail2ban 0.11 (jammy) has no nginx-bad-request filter (added in 1.0).
        canary = re.sub(r"(?ms)^\[nginx-bad-request\]$.*?(?=^\[)", "", canary)
        canary_jails.remove("nginx-bad-request")
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
    rc, out, err = run([sys.executable, "-I", "-c", "import ast,sys; ast.parse(open(sys.argv[1]).read(), "
                        "feature_version=(3, 10))", lab.a.helper])
    expect("helper", "S14 parses as Python 3.10", (rc, err.strip()), (0, ""))
    txt = read(lab.a.helper)
    check("helper", "S14 no Jinja delimiters in the helper (it travels inside an argv)",
          not re.search(r"\{\{|\{%|\{#", txt))


# --- S13, S15, S16: a real fail2ban 1.0.2 server, as this user ---------------------

class Server:
    LAB_ACTION = ("[Definition]\nactionstart = echo \"start <name> port=<port>\" >> {r}/actions.log\n"
                  "actionstop = echo \"stop <name> port=<port>\" >> {r}/actions.log\nactioncheck =\n"
                  "actionban = echo \"ban <name> <ip> port=<port>\" >> {r}/actions.log\n"
                  "actionunban = echo \"unban <name> <ip> port=<port>\" >> {r}/actions.log\n")

    def __init__(self, lab, dist, conf, name, fresh=True):
        self.lab, self.dist, self.conf = lab, dist, conf
        self.r = os.path.join(lab.w, "srv", name)
        if fresh:
            shutil.rmtree(self.r, ignore_errors=True)
        os.makedirs(self.r, exist_ok=True)
        write(os.path.join(conf, "fail2ban.local"),
              "[Definition]\nloglevel = INFO\nlogtarget = %s/f2b.log\nsocket = %s/f2b.sock\n"
              "pidfile = %s/f2b.pid\ndbfile = %s/f2b.sqlite3\ndbpurgeage = 1d\n" % ((self.r,) * 4))
        write(os.path.join(conf, "action.d/lab.conf"), self.LAB_ACTION.format(r=self.r))
        self.srv = os.path.join(lab.w, "bin", "f2bs-" + dist)
        write(self.srv, "#!/bin/sh\ncd / || exit 2\nexec %s -I -B -c \"%s\" %s \"$@\"\n"
              % (lab.a.server_python, SERVER_CODE, lab.pypath(dist)), 0o755)
        for f in ("auth.log", "rec.log", "auth2.log"):
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
    stubs = os.path.join(lab.w, "stubs")
    write(os.path.join(stubs, "dpkg-query"),
          "#!/bin/sh\n# lab stub: fail2ban 1.0.2 is installed\ncase \"$*\" in\n"
          "  *Version*) printf 'ii  1.0.2-3ubuntu0.1' ;;\n  *) printf 'ii ' ;;\nesac\n", 0o755)
    write(os.path.join(stubs, "systemctl"),
          "#!/bin/sh\n# lab stub: fail2ban.service active and enabled\ncase \"$1\" in\n"
          "  is-active) echo active ;;\n  is-enabled) echo enabled ;;\n  *) exit 1 ;;\nesac\n", 0o755)
    # The same, with fail2ban on hold (apt-mark hold): dpkg says "hi".
    stubs_held = os.path.join(lab.w, "stubs-held")
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
        t = keep[0] if keep else lab.tree(d, files, "s16-" + name)
        s = Server(lab, d, t, keep[1] if keep else "s16-" + name, fresh=not keep)
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
              "_f2b_backup_dir": os.path.join(lab.w, ptag, "backup-" + name), "ssh_port": 22}
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
        res = {"rc": rc, "out": out + err, "srv": s, "t": t, "before": before, "name": "s16-" + name}
        res["after"] = {"pid": s.pid(), "sshd": s.banned("sshd"), "recidive": s.banned("recidive"),
                        "newlog": s.log()[before["log"]:], "actions": s.actions(), "jails": s.jails(),
                        "maxretry": s.cli("get", "sshd", "maxretry")[1].strip(),
                        "jail.local": (read(os.path.join(t, "jail.local"))
                                       if os.path.exists(os.path.join(t, "jail.local")) else None)}
        s.stop()
        write(os.path.join(lab.w, "s16-%s-%s.log" % (os.path.basename(playbook_bin), name)), out + err)
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
        r2 = case("nginx2", None, {"lab_nginx": True}, keep=(r["t"], "s16-nginx"))
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
    ap.add_argument("--ansible", action="append", default=[])
    a = ap.parse_args()
    lab = Lab(a)
    template_checks(lab)
    for d in a.dists.split():
        config_checks(lab, d)
    if a.server_python and a.server_dist in a.dists.split():
        s13_server(lab, a.server_dist)
        s15_drift(lab, a.server_dist)
        for pb in a.ansible:
            s16_ansible(lab, a.server_dist, pb)
    elif a.server_python:
        print("SKIP  server checks: %s is not in --dists" % a.server_dist)
    else:
        print("SKIP  S13 S15 S16: no --server-python (a Python that imports asyncore)")
    print("\n%d passed, %d failed" % (PASSES[0], len(FAILS)))
    for f in FAILS:
        print("  FAILED: " + f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
