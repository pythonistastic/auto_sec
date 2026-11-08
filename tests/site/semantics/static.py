#!/usr/bin/env python3
"""Static checks of the roles for auto_sec 0.6 (plan 6.1, T-S2 static part).

Usage: python3 tests/site/semantics/static.py [REPO]

Reads every task file under roles/ (YAML, walking block/rescue/always) and
every text file of the roles for refusal and note IDs. Prints one PASS or
FAIL line per check and exits 1 when any check fails.

Checks:
  plan-NN   roles/NN-* sets _plan_NN (the plan contract; 00-plan reads it)
  ids       an ID R<NN>-..., M<NN>-..., N<NN>-... or W<NN>-... appears (outside
            comments) only in roles/NN-* (R00 also in roles/00-plan,
            roles/09-watcher and site.yml); M-P<n> and N-P<n> only in
            roles/autosec-apt. So no two roles can use the same ID.
  modules   no apt, ufw or sysctl module anywhere; cron only in role 07
  sysctl    no write module has /etc/sysctl.conf as its destination
  audit     no command runs augenrules, auditctl -R or restarts auditd
  absent    roles 08 and 09 have no task with state: absent
  sudoers   only role 01 writes under /etc/sudoers.d
  enable    systemd tasks with enabled: true only in roles 04-07
"""
import os
import re
import sys

import yaml

REPO = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "..", ".."))
ROLES = os.path.join(REPO, "roles")

FAILS = 0


def report(ok, name, detail=""):
    global FAILS
    if not ok:
        FAILS += 1
    print("%s  [static] %s%s" % ("PASS" if ok else "FAIL", name, (": " + detail) if detail else ""))


TASK_KEYWORDS = {
    "name", "when", "tags", "register", "vars", "loop", "loop_control", "become", "become_user",
    "become_method", "become_flags", "check_mode", "changed_when", "failed_when", "ignore_errors",
    "ignore_unreachable", "notify", "environment", "args", "delegate_to", "delegate_facts", "run_once",
    "until", "retries", "delay", "no_log", "diff", "block", "rescue", "always", "listen",
    "any_errors_fatal", "throttle", "timeout", "collections", "module_defaults", "debugger", "async",
    "poll", "connection", "remote_user", "port", "action", "local_action",
}


def module_of(task):
    for k in task:
        if k in TASK_KEYWORDS or k.startswith("with_"):
            continue
        return k
    return task.get("action") or task.get("local_action")


def short(mod):
    mod = str(mod or "")
    for p in ("ansible.builtin.", "ansible.legacy.", "community.general.", "ansible.posix."):
        if mod.startswith(p):
            return mod[len(p):], p.rstrip(".")
    return mod, ""


def walk(tasks):
    for t in tasks or []:
        if not isinstance(t, dict):
            continue
        yield t
        for k in ("block", "rescue", "always"):
            if k in t:
                yield from walk(t[k])


def role_of(path):
    rel = os.path.relpath(path, ROLES).replace(os.sep, "/")
    return rel.split("/")[0]


task_files = []
for root, _dirs, files in os.walk(ROLES):
    if "__pycache__" in root:
        continue
    for f in files:
        if f.endswith((".yml", ".yaml")) and os.path.basename(root) in ("tasks", "handlers"):
            task_files.append(os.path.join(root, f))
task_files.sort()

tasks = []  # (role, file, task)
for path in task_files:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or []
    for t in walk(data):
        tasks.append((role_of(path), os.path.relpath(path, REPO).replace(os.sep, "/"), t))

# --- plan-NN ---------------------------------------------------------------
for nn in ["%02d" % i for i in range(1, 12)]:
    dirs = [d for d in os.listdir(ROLES) if d.startswith(nn + "-")]
    key = "_plan_" + nn
    found = False
    for role, _f, t in tasks:
        if role in dirs and short(module_of(t))[0] == "set_fact":
            args = t.get(module_of(t)) or {}
            if isinstance(args, dict) and key in args:
                found = True
    report(found, "plan-" + nn, "" if found else "no set_fact of %s in roles/%s-*" % (key, nn))

# --- ids -------------------------------------------------------------------
ID_RE = re.compile(r"\b([RMNW])([0-9]{2})-[A-Z]{0,2}[0-9]+[a-z]?\b")
GUARD_RE = re.compile(r"\b([MN])-P[0-9]+\b")
bad = []
scan = [os.path.join(REPO, "site.yml")]
for root, _dirs, files in os.walk(ROLES):
    if "__pycache__" in root:
        continue
    scan += [os.path.join(root, f) for f in files]
for path in sorted(scan):
    rel = os.path.relpath(path, REPO).replace(os.sep, "/")
    role = role_of(path) if rel.startswith("roles/") else "site.yml"
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except (UnicodeDecodeError, OSError):
        continue
    for n, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        for m in ID_RE.finditer(line):
            nn = m.group(2)
            ok = role.startswith(nn + "-") or (nn == "00" and role in ("00-plan", "09-watcher", "site.yml"))
            if not ok:
                bad.append("%s:%d %s" % (rel, n, m.group(0)))
        for m in GUARD_RE.finditer(line):
            if role != "autosec-apt":
                bad.append("%s:%d %s" % (rel, n, m.group(0)))
report(not bad, "ids", "; ".join(bad[:20]))

# --- modules, sysctl, audit, absent, sudoers, enable -------------------------
WRITE_MODULES = {"copy", "template", "lineinfile", "blockinfile", "file", "replace", "ini_file", "assemble", "get_url", "unarchive"}
mod_bad, sysctl_bad, audit_bad, absent_bad, sudo_bad, enable_bad = [], [], [], [], [], []
AUDIT_RE = re.compile(r"(^|[\s;&|(`'\"])(augenrules|/sbin/augenrules|/usr/sbin/augenrules)(\s|$)|auditctl\s+-R|systemctl\s+(restart|reload|try-restart|try-reload-or-restart)\s+auditd|service\s+auditd\s+restart")
for role, f, t in tasks:
    mod = module_of(t)
    if mod in ("block", None):
        continue
    name, coll = short(mod)
    args = t.get(mod)
    where = "%s (%s)" % (f, t.get("name", "?"))
    if name in ("apt", "ufw", "sysctl") and coll in ("", "ansible.builtin", "ansible.legacy", "community.general", "ansible.posix"):
        mod_bad.append("%s uses %s" % (where, mod))
    if name == "cron" and not role.startswith("07-"):
        mod_bad.append("%s uses %s" % (where, mod))
    if isinstance(args, dict):
        dest = str(args.get("dest", args.get("path", args.get("name", ""))) or "")
        if name in WRITE_MODULES:
            if dest.strip() == "/etc/sysctl.conf":
                sysctl_bad.append(where)
            if "sudoers.d" in dest and not role.startswith("01-"):
                sudo_bad.append(where)
        if role.startswith(("08-", "09-")) and str(args.get("state", "")) == "absent":
            absent_bad.append(where)
        if name in ("systemd", "systemd_service", "service") and str(args.get("enabled", "")).lower() in ("true", "yes", "1", "on"):
            if not role.startswith(("04-", "05-", "06-", "07-")):
                enable_bad.append(where)
    if name in ("command", "shell", "raw", "script"):
        texts = []
        if isinstance(args, dict):
            argv = args.get("argv")
            if isinstance(argv, list):
                texts += [str(a) for a in argv]
            elif argv is not None:
                texts.append(str(argv))
            if args.get("cmd"):
                texts.append(str(args["cmd"]))
        elif args is not None:
            texts.append(str(args))
        for txt in texts:
            code = "\n".join(line for line in txt.splitlines() if not line.lstrip().startswith("#"))
            if AUDIT_RE.search(code):
                audit_bad.append(where)
report(not mod_bad, "modules", "; ".join(mod_bad[:10]))
report(not sysctl_bad, "sysctl", "; ".join(sysctl_bad[:10]))
report(not audit_bad, "audit", "; ".join(audit_bad[:10]))
report(not absent_bad, "absent", "; ".join(absent_bad[:10]))
report(not sudo_bad, "sudoers", "; ".join(sudo_bad[:10]))
report(not enable_bad, "enable", "; ".join(enable_bad[:10]))
report(len(tasks) > 300, "parsed", "%d tasks in %d files" % (len(tasks), len(task_files)))

sys.exit(1 if FAILS else 0)
