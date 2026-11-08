#!/usr/bin/env python3
"""cve-semantics checks for role 11 (LAB ONLY; run by run.sh).

  h1-h3  the known 0.2-0.5 sha256 in roles/11-cve-watch/defaults/main.yml
         equal the files rendered from git history (needs the history)
  p1-p6  role 11's plan.yml (ansible-playbook, current user): ownership
         proof (R11-2), app_dir (R11-1), what changes, the daemon-reload
         refusal (R11-3)
  s1     the scanner counts pending OS updates even without an app folder
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys

import yaml

PASSED, FAILED = [], []


def check(name, ok, detail=""):
    (PASSED if ok else FAILED).append(name)
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, "" if ok else "\n      " + str(detail)[-1500:]))


def write(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)
    os.chmod(path, mode)


def git(root, *args):
    return subprocess.run(["git", "-C", root] + list(args), capture_output=True, check=False)


def legacy_files(root):
    """{'scanner': {sha: bytes}, 'service': ..., 'timer': ...} from git history, or None."""
    log = git(root, "log", "--format=%h", "--", "roles/11-cve-watch")
    commits = log.stdout.decode().split()
    if log.returncode != 0 or len(commits) < 2:
        return None
    out = {"scanner": {}, "service": {}, "timer": {}}
    for c in commits:
        py = git(root, "show", "%s:roles/11-cve-watch/files/cve_watch.py" % c).stdout
        if not py:
            continue
        out["scanner"][hashlib.sha256(py).hexdigest()] = py
        tasks = yaml.safe_load(git(root, "show", "%s:roles/11-cve-watch/tasks/main.yml" % c).stdout) or []
        for t in tasks:
            cp = t.get("ansible.builtin.copy") or {}
            if cp.get("dest") == "/etc/systemd/system/cve-watch.service":
                b = cp["content"].encode()
                out["service"][hashlib.sha256(b).hexdigest()] = b
            if cp.get("dest") == "/etc/systemd/system/cve-watch.timer":
                src = cp["content"]
                m = re.search(r"\{\{.*?\}\}", src)
                for hour in range(24):
                    b = (src[:m.start()] + "%02d" % hour + src[m.end():]).encode()
                    out["timer"][hashlib.sha256(b).hexdigest()] = b
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--here", required=True)
    ap.add_argument("--ansible", action="append", default=[])
    a = ap.parse_args()
    defaults = yaml.safe_load(open(os.path.join(a.root, "roles/11-cve-watch/defaults/main.yml")))
    known = defaults["_cve_legacy_sha256"]

    legacy = legacy_files(a.root)
    if legacy is None:
        print("SKIP  h1-h3 and p2: no git history of roles/11-cve-watch here (CI: fetch-depth: 0)")
    else:
        for n in ("scanner", "service", "timer"):
            check("h %s: the known sha256 are exactly the git history's files (%d)" % (n, len(legacy[n])),
                  sorted(known[n]) == sorted(legacy[n]), (sorted(known[n]), sorted(legacy[n])))

    # s1: the scanner's timer mode counts OS updates without an app folder
    spec = importlib.util.spec_from_file_location("cve_watch", os.path.join(a.root, "roles/11-cve-watch/files/cve_watch.py"))
    cw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cw)
    w = os.path.join(a.work, "s1")
    os.makedirs(w, exist_ok=True)
    write(os.path.join(w, "conf"), "[cve]\nhost_label = lab\napp_dir = %s/no-such-app\ninclude_os = true\n"
          "telegram_bot_token = CHANGE_ME\ntelegram_chat_id = CHANGE_ME\n" % w)
    cw.CONF, cw.STATE, cw.REPORT_DIR = os.path.join(w, "conf"), os.path.join(w, "seen.json"), os.path.join(w, "reports")
    cw.pending_os_security_updates = lambda: 3
    rc = cw.main_timer()
    rep = "".join(open(os.path.join(cw.REPORT_DIR, f)).read() for f in os.listdir(cw.REPORT_DIR)) if os.path.isdir(cw.REPORT_DIR) else ""
    check("s1 no app folder: rc 0, report still counts 3 pending OS security updates",
          rc == 0 and "pending OS security updates: 3" in rep and "does not exist" in rep, rep)

    for pb in a.ansible:
        tag = os.path.basename(os.path.dirname(os.path.dirname(pb)))

        def run(name, files=None, app=True, units="", ndr="", extra=None, inactive=()):
            d = os.path.join(a.work, tag, name)
            shutil.rmtree(d, ignore_errors=True)
            t = {"scanner": d + "/opt/cve-watch/cve_watch.py", "conf": d + "/opt/cve-watch/cve-watch.conf",
                 "service": d + "/etc/systemd/system/cve-watch.service", "timer": d + "/etc/systemd/system/cve-watch.timer"}
            os.makedirs(d + "/etc/systemd/system", exist_ok=True)
            for k, v in (files or {}).items():
                write(t[k], v)
            if app:
                os.makedirs(d + "/app", exist_ok=True)
            stub = os.path.join(d, "stub")
            # list-units --all: every unit named in ndr is loaded; those in
            # `inactive` are loaded but not running (R11-3 asks them too).
            lu = "".join("%s loaded %s\n" % (u, "inactive dead x" if u in inactive else "active running x")
                         for u in re.findall(r"^Id=(\S+)$", ndr, re.M))
            write(os.path.join(stub, "systemctl"),
                  "#!/bin/sh\ncase \"$*\" in\n  list-units*) printf '%%s' '%s' ;;\n  *NeedDaemonReload*) printf '%%s' '%s' ;;\n"
                  "  *) printf '%%s' '%s' ;;\nesac\n" % (lu, ndr, units), 0o755)
            ev = {"_cve_targets": t, "_cve_dir": d + "/opt/cve-watch", "_cve_sim_dir": d + "/run/cve-sim",
                  "_cve_timer_link": d + "/etc/systemd/system/timers.target.wants/cve-watch.timer",
                  "app_dir": d + "/app", "cve_watch_enabled": True, "telegram_bot_token": "CHANGE_ME",
                  "telegram_chat_id": "CHANGE_ME"}
            ev.update(extra or {})
            evf = os.path.join(d, "ev.json")
            write(evf, json.dumps(ev))
            env = dict(os.environ, LC_ALL="C.UTF-8", ANSIBLE_NOCOLOR="1", ANSIBLE_LOCALHOST_WARNING="False",
                       ANSIBLE_INVENTORY_UNPARSED_WARNING="False", ANSIBLE_DEPRECATION_WARNINGS="False",
                       ANSIBLE_ROLES_PATH=os.path.join(a.root, "roles"), PATH=stub + ":" + os.environ["PATH"])
            r = subprocess.run([pb, "-i", "localhost,", os.path.join(a.here, "play.yml"), "-e", "@" + evf],
                               capture_output=True, text=True, env=env)
            out = r.stdout + r.stderr
            write(os.path.join(d, "log"), out)
            m = re.search(r"LAB write=(.*?) reload=(\w+) link=(\w+) start=(\w*) items=(\[.*?\])", out)
            return r.returncode, out, m.groups() if m else None

        loaded = ("Id=cve-watch.service\nLoadState=loaded\nActiveState=inactive\nUnitFileState=static\n\n"
                  "Id=cve-watch.timer\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n")
        rc, out, g = run("p1")
        check("p1 %s nothing there: 4 writes, link, start, no reload" % tag,
              rc == 0 and g and g[0] == "['scanner', 'conf', 'service', 'timer']" and g[1:4] == ("False", "True", "start"),
              (rc, g, out[-1200:]))
        if legacy is not None:
            sc = legacy["scanner"]["7962b8f755963ff6cecfcd0003800529ad67796fd7cbe6ef0faa22a1fab15ff3"]
            sv = next(iter(legacy["service"].values()))
            tm = [v for v in legacy["timer"].values() if b" 06:20:00" in v][0]
            conf = b"# Managed by Ansible. Permissions 0600, root only.\n[cve]\nhost_label = x\n"
            rc, out, g = run("p2", files={"scanner": sc, "service": sv, "timer": tm, "conf": conf}, units=loaded)
            check("p2 %s auto_sec 0.5's exact files: accepted, all replaced, reload (loaded units change), active timer restarted" % tag,
                  rc == 0 and g and g[0] == "['scanner', 'conf', 'service', 'timer']" and g[1] == "True" and g[3] == "restart",
                  (rc, g, out[-1200:]))
            rc, out, g = run("p2b", files={"scanner": sc, "service": sv, "timer": tm, "conf": conf}, units=loaded,
                             ndr="Id=ssh.service\nNeedDaemonReload=yes\n\nId=cve-watch.service\nNeedDaemonReload=no\n")
            check("p6 %s a loaded unit changes and ssh.service has unloaded edits: R11-3" % tag,
                  rc != 0 and "unit edits systemd has not loaded yet: ssh.service" in out, out[-1200:])
            rc, out, g = run("p2c", files={"scanner": sc, "service": sv, "timer": tm, "conf": conf}, units=loaded,
                             ndr="Id=backup.service\nNeedDaemonReload=yes\n\nId=cve-watch.service\nNeedDaemonReload=no\n",
                             inactive=("backup.service",))
            check("p6 %s an INACTIVE unit with unloaded edits counts too: R11-3" % tag,
                  rc != 0 and "unit edits systemd has not loaded yet: backup.service" in out, out[-1200:])
        rc, out, g = run("p3", files={"service": "[Unit]\nDescription=mine\n"})
        check("p3 %s a cve-watch.service of yours: R11-2" % tag,
              rc != 0 and "is not auto_sec's" in out and "cve-watch.service" in out, out[-1200:])
        rc, out, g = run("p3b", files={"conf": "# Managed by Ansible. Permissions 0600, root only.\n[cve]\n"})
        check("p3 %s 0.5's conf line 1 without 0.5's scanner proves nothing: R11-2" % tag,
              rc != 0 and "cve-watch.conf" in out, out[-1200:])
        rc, out, g = run("p5", app=False)
        check("p5 %s app_dir missing: R11-1" % tag, rc != 0 and "does not exist on" in out, out[-1200:])
        # layer 05 (selected, its plan saw app_dir absent) creates it in this run
        rc, out, g = run("p5b", app=False, extra={"_layer_05": True, "_sel_05": True, "_l05_now": {"appdir": "absent"}})
        check("p5 %s app_dir missing, but layer 05 creates it in this run: no R11-1" % tag,
              rc == 0 and "does not exist on" not in out, out[-1200:])
        rc, out, g = run("p5c", app=False, extra={"_layer_05": True, "_sel_05": False, "_l05_now": {"appdir": "absent"}})
        check("p5 %s app_dir missing, layer 05 not selected by the tags: R11-1" % tag,
              rc != 0 and "does not exist on" in out, out[-1200:])
        # p4: a second plan on the files exactly as 0.6 renders them: nothing to write
        d1 = os.path.join(a.work, tag, "p1")
        rendered = {}
        for k, src in (("service", "cve-watch.service.j2"), ("timer", "cve-watch.timer.j2")):
            rendered[k] = open(os.path.join(a.root, "roles/11-cve-watch/templates", src)).read() \
                .replace("{{ '%02d' | format(cve_watch_hour | int) }}", "06")
        rendered["scanner"] = open(os.path.join(a.root, "roles/11-cve-watch/files/cve_watch.py")).read()
        units_on = ("Id=cve-watch.service\nLoadState=loaded\nActiveState=inactive\nUnitFileState=static\n\n"
                    "Id=cve-watch.timer\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n")
        rc, out, g = run("p4", files=rendered, units=units_on)
        check("p4 %s files already as 0.6 writes them (but the conf): only the conf is written, no reload, no start" % tag,
              rc == 0 and g and g[0] == "['conf']" and g[1:4] == ("False", "False", ""), (rc, g, out[-1200:]))
        del d1

    print("== %d passed, %d failed" % (len(PASSED), len(FAILED)))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
