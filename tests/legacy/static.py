"""Static checks of roles 08 and 09 in auto_sec 0.6 (keep-only).

Usage: python3 static.py <repo root>
Prints one PASS/FAIL line per check; exit 1 when one fails.

Roles 08 and 09 must install, write, start and delete nothing. So:
  - the roles hold only defaults/main.yml and tasks/*.yml (no handlers,
    templates, files, vars or meta);
  - every task uses a read-only module: set_fact, debug, assert, stat,
    slurp, or command with an argv list whose program is grep or
    `systemctl is-active`, with changed_when: false and check_mode: false;
  - no task notifies, delegates, or changes user;
  - legacy.yml sets _plan_08 / _plan_09 to [] in its first task.
"""
import os
import sys

import yaml

ROOT = sys.argv[1]
ROLES = {"08-detection": "_plan_08", "09-watcher": "_plan_09"}
ALLOWED = {
    "ansible.builtin.set_fact", "ansible.builtin.debug", "ansible.builtin.assert",
    "ansible.builtin.stat", "ansible.builtin.slurp", "ansible.builtin.command",
}
TASK_KEYS = {
    "name", "when", "block", "vars", "loop", "loop_control", "register",
    "changed_when", "failed_when", "check_mode", "tags", "no_log",
}
fails = 0


def report(ok, what):
    global fails
    print(("PASS  %-12s %s" if ok else "FAIL  %-12s %s") % ("static", what))
    if not ok:
        fails += 1


def walk(tasks):
    for t in tasks or []:
        if "block" in t:
            yield t
            yield from walk(t["block"])
            for k in ("rescue", "always"):
                yield from walk(t.get(k))
        else:
            yield t


for role, plan in ROLES.items():
    rdir = os.path.join(ROOT, "roles", role)
    files = sorted(os.path.relpath(os.path.join(d, f), rdir).replace(os.sep, "/")
                   for d, _, fs in os.walk(rdir) for f in fs)
    extra = [f for f in files if f != "defaults/main.yml" and not
             (f.startswith("tasks/") and f.endswith(".yml") and f.count("/") == 1)]
    report(not extra, "%s holds only defaults/main.yml and tasks/*.yml%s"
           % (role, (": also " + ", ".join(extra)) if extra else ""))
    report("tasks/main.yml" not in files,
           "%s has no tasks/main.yml (site.yml includes tasks_from: legacy)" % role)
    for f in files:
        if not f.startswith("tasks/"):
            continue
        doc = yaml.safe_load(open(os.path.join(rdir, f))) or []
        bad = []
        for t in walk(doc):
            name = t.get("name", "?")
            unknown = set(t) - TASK_KEYS - ALLOWED
            if unknown:
                bad.append("%s: keys %s" % (name, sorted(unknown)))
            if "block" in t:
                continue
            mods = [k for k in t if k in ALLOWED]
            if len(mods) != 1:
                bad.append("%s: module not allowed" % name)
                continue
            if mods[0] == "ansible.builtin.command":
                argv = t[mods[0]].get("argv") if isinstance(t[mods[0]], dict) else None
                if isinstance(argv, str) and argv.startswith("{{"):
                    prog = "systemctl" if "'systemctl', 'is-active'" in argv else "?"
                    sub = "is-active" if prog == "systemctl" else "?"
                elif isinstance(argv, list) and argv:
                    prog, sub = argv[0], (argv[1] if len(argv) > 1 else "")
                else:
                    prog, sub = "?", "?"
                if not (prog == "grep" or (prog == "systemctl" and sub == "is-active")):
                    bad.append("%s: command %s %s" % (name, prog, sub))
                if t.get("changed_when") is not False or t.get("check_mode") is not False:
                    bad.append("%s: needs changed_when: false and check_mode: false" % name)
        report(not bad, "%s/%s uses only read-only tasks%s"
               % (role, f, (": " + "; ".join(bad)) if bad else ""))
    legacy = yaml.safe_load(open(os.path.join(rdir, "tasks", "legacy.yml")))
    first = legacy[0]["block"][0].get("ansible.builtin.set_fact", {})
    report(first.get(plan) == [], "%s/tasks/legacy.yml starts with %s: []" % (role, plan))

sys.exit(1 if fails else 0)
