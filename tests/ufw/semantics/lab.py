#!/usr/bin/env python3
"""ufw-semantics checks (called by run.sh; LAB ONLY, never against a server).

Every lab tree is a copy of the pinned ufw package's stock files (ENABLED=no,
/etc/default/ufw, /etc/ufw/sysctl.conf, the rule files and their md5 lists),
changed with ufw's OWN commands (real ufw code, --rootdir/--datadir). /proc,
/sys/class/net, systemctl and ss come from fixtures. The turn-on helper reads
them with its lab-only flags (--root, --proc, --ufw, --systemctl, --ss).

  u1-u24  the helper: verdicts, notes, and for every planned add the real
          ufw's `show added` after the commands equals the helper's
          expected_after (the U7 check of role 03 main)
  a1-a8   role 03's own task files (preflight.yml, ufw-add.yml, ufw.yml up to
          its --check stop) run by
          ansible-playbook against lab trees (--ansible)
"""
import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys

FAILED = []
PASSED = []


def check(name, ok, detail=""):
    (PASSED if ok else FAILED).append(name)
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, "" if ok else "\n      " + str(detail)[:1500]))


def expect(name, got, want, detail=""):
    check(name, got == want, "got %r, want %r %s" % (got, want, detail))


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


class Lab:
    def __init__(self, a):
        self.a = a
        self.w = os.path.abspath(a.work)
        os.makedirs(self.w, exist_ok=True)
        self.n = 0

    # --- ufw config trees ----------------------------------------------------
    def tree(self, name, default=None, sysctl=None, edit_before=False, init_exec=False, net=None):
        """A fresh ufw tree (package defaults, ENABLED=no). default: lines to
        set in /etc/default/ufw; sysctl: replaces /etc/ufw/sysctl.conf;
        net: {ifname: uevent text} under sys/class/net."""
        src = self.a.src
        t = os.path.join(self.w, "trees", name)
        shutil.rmtree(t, ignore_errors=True)
        os.makedirs(os.path.join(t, "etc/ufw/applications.d"))
        os.makedirs(os.path.join(t, "etc/default"))
        os.makedirs(os.path.join(t, "lib/ufw"))
        shutil.copy(os.path.join(src, "etc/default/ufw"), os.path.join(t, "etc/default/ufw"))
        shutil.copy(os.path.join(src, "usr/share/ufw/ufw.conf"), os.path.join(t, "etc/ufw/ufw.conf"))
        shutil.copy(os.path.join(src, "etc/ufw/sysctl.conf"), os.path.join(t, "etc/ufw/sysctl.conf"))
        for f in ("before.rules", "after.rules", "before6.rules", "after6.rules", "user.rules", "user6.rules"):
            shutil.copy(os.path.join(src, "usr/share/ufw/iptables", f), os.path.join(t, "etc/ufw", f))
        shutil.copytree(os.path.join(src, "usr/share/ufw"), os.path.join(t, "usr/share/ufw"))
        for d in ("usr/lib/ufw", "lib/ufw"):  # 0.36.1 and Debian 12: /lib/ufw
            if os.path.isdir(os.path.join(src, d)):
                shutil.copytree(os.path.join(src, d), os.path.join(t, "lib/ufw"), dirs_exist_ok=True)
        if default:
            p = os.path.join(t, "etc/default/ufw")
            lines = open(p).read().splitlines()
            for k, v in default.items():
                lines = [ln for ln in lines if not ln.startswith(k + "=")] + ["%s=%s" % (k, v)]
            write(p, "\n".join(lines) + "\n")
        if sysctl is not None:
            write(os.path.join(t, "etc/ufw/sysctl.conf"), sysctl)
        if edit_before:
            with open(os.path.join(t, "etc/ufw/before.rules"), "a") as f:
                f.write("# an edit of yours\n")
        if init_exec:
            write(os.path.join(t, "etc/ufw/before.init"), "#!/bin/sh\nexit 0\n", 0o755)
        os.makedirs(os.path.join(t, "sys/class/net/lo"), exist_ok=True)
        write(os.path.join(t, "sys/class/net/lo/uevent"), "INTERFACE=lo\nIFINDEX=1\n")
        for ifn, ue in (net or {}).items():
            write(os.path.join(t, "sys/class/net", ifn, "uevent"), ue)
        for root, dirs, files in os.walk(t):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o755)
        return t

    def wrapper(self, t, active=False):
        p = os.path.join(self.w, "bin", "ufw-%s%s" % (os.path.basename(t), "-active" if active else ""))
        write(p, "#!/bin/sh\nUFW_LAB_ACTIVE=%d PYTHONPATH=%s exec python3 %s --rootdir=%s --datadir=%s \"$@\"\n" % (
            1 if active else 0, os.path.join(self.a.pkg, "usr/lib/python3/dist-packages"),
            os.path.join(self.a.pkg, "usr/sbin/ufw"), t, t), 0o755)
        return p

    def ufw(self, t, *args, active=False):
        p = subprocess.run([self.wrapper(t, active)] + list(args), capture_output=True, text=True,
                           env=dict(os.environ, LANG="C", LC_ALL="C"))
        return p.returncode, p.stdout, p.stderr

    def added(self, t):
        rc, out, err = self.ufw(t, "show", "added")
        return [ln for ln in out.splitlines()[1:] if ln.startswith("ufw ")]

    # --- /proc, systemctl and ss fixtures --------------------------------------
    @staticmethod
    def _hex(ip):
        a = ipaddress.ip_address(ip)
        if a.version == 4:
            return a.packed[::-1].hex().upper()
        return "".join(a.packed[i:i + 4][::-1].hex().upper() for i in range(0, 16, 4))

    def proc(self, name, socks=(), sysvals=None, inet6=()):
        """socks: (proto, ip, port, state, remote) with proto tcp|udp; state
        LISTEN/CLOSE/ESTAB; remote 'ip:port' or ''."""
        p = os.path.join(self.w, "proc", name)
        shutil.rmtree(p, ignore_errors=True)
        files = {"tcp": [], "tcp6": [], "udp": [], "udp6": []}
        st = {"LISTEN": "0A", "CLOSE": "07", "ESTAB": "01"}
        for i, (proto, ip, port, state, remote) in enumerate(socks):
            v6 = ":" in ip
            fn = proto + ("6" if v6 else "")
            rip, rport = (remote.rsplit(":", 1) if remote else (("::" if v6 else "0.0.0.0"), "0"))
            files[fn].append("%4d: %s:%04X %s:%04X %s 00000000:00000000 00:00000000 00000000     0        0 %d 1"
                             % (i, self._hex(ip), port, self._hex(rip), int(rport), st[state], 1000 + i))
        hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        for fn, lines in files.items():
            write(os.path.join(p, "net", fn), hdr + "".join(ln + "\n" for ln in lines))
        write(os.path.join(p, "net", "if_inet6"),
              "00000000000000000000000000000001 01 80 10 80       lo\n"
              + "".join("%s 02 40 00 80     eth0\n" % self._hex(a).lower() for a in inet6))
        vals = {
            "net/ipv4/ip_forward": "0", "net/ipv6/conf/all/forwarding": "0",
            "net/ipv4/conf/all/accept_redirects": "1", "net/ipv4/conf/default/accept_redirects": "1",
            "net/ipv6/conf/all/accept_redirects": "1", "net/ipv6/conf/default/accept_redirects": "1",
            "net/ipv4/icmp_echo_ignore_broadcasts": "1", "net/ipv4/icmp_ignore_bogus_error_responses": "1",
            "net/ipv4/icmp_echo_ignore_all": "0", "net/ipv4/conf/all/log_martians": "0",
            "net/ipv4/conf/default/log_martians": "0",
        }
        vals.update(sysvals or {})
        for k, v in vals.items():
            write(os.path.join(p, "sys", k), v + "\n")
        return p

    def stubs(self, name, units=None, ss=""):
        d = os.path.join(self.w, "stubs", name)
        u = {"is-active firewalld.service": "inactive", "is-enabled nftables.service": "disabled",
             "is-enabled netfilter-persistent.service": "", "is-enabled ufw.service": "enabled"}
        u.update(units or {})
        case = "".join('  "%s") echo "%s" ;;\n' % (k, v) for k, v in u.items())
        write(os.path.join(d, "systemctl"), '#!/bin/sh\ncase "$1 $2" in\n%s  *) exit 1 ;;\nesac\n' % case, 0o755)
        write(os.path.join(d, "ss"), "#!/bin/sh\ncat <<'EOF'\n%sEOF\n" % ss, 0o755)
        return d

    def helper(self, t, p, want, ssh_port=22, ctrl="", no_ufw=False, stubs=None, active=False):
        s = stubs or self.stubs("default")
        argv = [sys.executable, "-I", "-c", open(self.a.helper).read(), "--want", json.dumps(want),
                "--ssh-port", str(ssh_port), "--controller-ip", ctrl, "--root", t, "--proc", p,
                "--ufw", json.dumps([self.wrapper(t, active)]), "--systemctl", os.path.join(s, "systemctl"),
                "--ss", os.path.join(s, "ss")]
        if no_ufw:
            argv.append("--no-ufw")
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode != 0:
            return {"_error": r.stderr[-800:]}
        return json.loads(r.stdout)


# What role 03's ufw-preflight.yml builds from the variables (_fw_items), for
# the helper-level checks. The Ansible checks (a*) run the real tasks.
def items(ssh_port=22, ssh_rule="limit", office="", inbound=(), egress=False, extra=()):
    out = []
    p = str(ssh_port)
    if office:
        out.append({"id": "office", "kind": "office", "action": "allow", "dir": "in", "src": office, "port": p,
                    "proto": "tcp", "argv": ["prepend", "allow", "from", office, "to", "any", "port", p, "proto",
                                             "tcp", "comment", "auto_sec"]})
    if ssh_rule != "keep":
        out.append({"id": "ssh", "kind": "ssh", "action": ssh_rule, "dir": "in", "src": "", "port": p,
                    "proto": "tcp", "argv": [ssh_rule, p + "/tcp", "comment", "auto_sec"]})
    for i, it in enumerate(inbound, 1):
        port, proto, src, rule = str(it["port"]), it.get("proto", "tcp"), it.get("from", ""), it.get("rule", "allow")
        argv = ([rule, port + "/" + proto] if not src else
                [rule, "from", src, "to", "any", "port", port, "proto", proto]) + ["comment", "auto_sec"]
        out.append({"id": "in%d" % i, "kind": "inbound", "action": rule, "dir": "in", "src": src, "port": port,
                    "proto": proto, "argv": argv})
    if egress:
        base = [(53, "udp"), (53, "tcp"), (123, "udp"), (80, "tcp"), (443, "tcp")] + list(extra)
        for i, (port, proto) in enumerate(base, 1):
            out.append({"id": "out%d" % i, "kind": "egress", "action": "allow", "dir": "out", "src": "",
                        "port": str(port), "proto": proto,
                        "argv": ["allow", "out", "%d/%s" % (port, proto), "comment", "auto_sec"]})
    return out


def want(its, ssh_rule="limit", closed_ok=(), egress=False):
    return {"items": [{k: v for k, v in i.items() if k != "argv"} for i in its], "ssh_rule": ssh_rule,
            "closed_ok": list(closed_ok), "egress": egress}


def ids(r, key="verdicts"):
    return sorted(v["id"] for v in r.get(key, []))


def apply_and_compare(lab, t, its, r, egress_policy=False):
    """Role 03's U5-U7 with the real ufw: run the planned commands, then
    `show added` must equal the helper's expected_after."""
    add = [s["id"] for s in r["items"] if s["status"] == "add"]
    for it in its:
        if it["id"] in add:
            rc, out, err = lab.ufw(t, *it["argv"])
            if rc != 0:
                return False, "ufw %s failed: %s %s" % (" ".join(it["argv"]), out, err)
    if egress_policy:
        lab.ufw(t, "default", "deny", "outgoing")
    got = lab.added(t)
    return got == r["expected_after"], {"got": got, "expected": r["expected_after"]}


L_SS = ("tcp   LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=10,fd=6))\n"
        "tcp   LISTEN 0 511 0.0.0.0:25 0.0.0.0:* users:((\"master\",pid=11,fd=13))\n"
        "udp   UNCONN 0 0 0.0.0.0:51820 0.0.0.0:* users:((\"wg-x{}\",pid=12,fd=3))\n")


def helper_checks(lab):
    p0 = lab.proc("base", [("tcp", "0.0.0.0", 22, "LISTEN", ""), ("tcp", "::", 22, "LISTEN", ""),
                           ("tcp", "127.0.0.53", 53, "LISTEN", ""), ("udp", "127.0.0.1", 323, "CLOSE", ""),
                           ("udp", "0.0.0.0", 68, "CLOSE", "")])

    # u1 canary layout (limit 22, allow 80/443), nothing asked, ufw off: covered, no add
    t = lab.tree("u1")
    for c in (["limit", "22/tcp"], ["allow", "80/tcp"], ["allow", "443/tcp"]):
        lab.ufw(t, *c)
    before = lab.added(t)
    its = items()
    r = lab.helper(t, p0, want(its))
    expect("u1 canary layout off: ssh covered by 'limit 22/tcp', nothing to add, no refusal",
          (ids(r), [s["status"] for s in r.get("items", [])], r.get("expected_after") == before),
          ([], ["covered"], True))
    check("u1 canary layout: the helper changed no ufw file", lab.added(t) == before)

    # u2 fresh + enabled: limit 22 + 80 + 443 -> 3 adds; real ufw matches expected_after
    t = lab.tree("u2")
    its = items(inbound=[{"port": 80}, {"port": 443}])
    p = lab.proc("u2", [("tcp", "0.0.0.0", 22, "LISTEN", ""), ("tcp", "0.0.0.0", 80, "LISTEN", ""),
                        ("tcp", "::", 443, "LISTEN", "")])
    r = lab.helper(t, p, want(its))
    expect("u2 fresh + enabled: no refusal, 3 adds",
          (ids(r), [s["status"] for s in r.get("items", [])]), ([], ["add", "add", "add"]))
    ok, d = apply_and_compare(lab, t, its, r)
    check("u2 real ufw after the 3 commands == expected_after", ok, d)

    # u3 allow 22/tcp of yours + limit wanted -> covered (#8: no allow->limit)
    t = lab.tree("u3")
    lab.ufw(t, "allow", "22/tcp")
    r = lab.helper(t, p0, want(items()))
    expect("u3 'allow 22/tcp' + firewall_ssh_rule limit: covered, nothing added",
          ([s["status"] for s in r.get("items", [])], ids(r)), (["covered"], []))

    # u4 deny 8080 of yours + inbound 8080 -> R03-W2 (deny is not checkable) and R03-W3
    t = lab.tree("u4")
    lab.ufw(t, "deny", "8080/tcp")
    r = lab.helper(t, p0, want(items(inbound=[{"port": 8080}])))
    expect("u4 'deny 8080/tcp' + inbound 8080: R03-W2 and R03-W3", ids(r), ["R03-W2", "R03-W3"])

    # u5 a replace after the plan is caught by the exact list check (M03-W2)
    t = lab.tree("u5")
    its = items(inbound=[{"port": 443}])
    r = lab.helper(t, p0, want(its))
    lab.ufw(t, "deny", "443/tcp")  # appears between the plan and the commands
    ok, d = apply_and_compare(lab, t, its, r)
    check("u5 a rule replaced after the plan: show added != expected_after (M03-W2 fires)", not ok, d)

    # u6 app profile, route rule, interface rule -> R03-W2
    for n, cmd in (("u6a", ["allow", "in", "on", "eth0", "to", "any", "port", "53"]),
                   ("u6b", ["route", "allow", "51820/udp"]),
                   ("u6c", ["allow", "80,443/tcp"])):
        t = lab.tree(n)
        lab.ufw(t, "limit", "22/tcp")
        lab.ufw(t, *cmd)
        r = lab.helper(t, p0, want(items()))
        expect("%s rule '%s' auto_sec cannot check: R03-W2" % (n, " ".join(cmd)), ids(r), ["R03-W2"])

    # u7 SSH restricted to a network of yours + limit wanted -> R03-W4b; with keep -> fine
    t = lab.tree("u7")
    lab.ufw(t, "allow", "from", "198.51.100.0/24", "to", "any", "port", "22", "proto", "tcp")
    r = lab.helper(t, p0, want(items(), ssh_rule="limit"), ctrl="198.51.100.9")
    expect("u7 restricted SSH + limit: R03-W4b", ids(r), ["R03-W4b"])
    r = lab.helper(t, p0, want(items(ssh_rule="keep"), ssh_rule="keep"), ctrl="198.51.100.9")
    expect("u7 restricted SSH + keep, controller inside: no refusal", ids(r), [])
    r = lab.helper(t, p0, want(items(ssh_rule="keep"), ssh_rule="keep"), ctrl="203.0.113.50")
    expect("u7 restricted SSH + keep, controller outside: R03-W4", ids(r), ["R03-W4"])

    # u8 no SSH rule and keep -> R03-W4
    t = lab.tree("u8")
    r = lab.helper(t, p0, want(items(ssh_rule="keep"), ssh_rule="keep"))
    expect("u8 no SSH rule, firewall_ssh_rule keep: R03-W4", ids(r), ["R03-W4"])

    # u9 listeners: 25/tcp, 51820/udp unconnected -> R03-W5; connected UDP,
    # loopback, 68 skipped; closed_ok passes
    t = lab.tree("u9")
    p = lab.proc("u9", [("tcp", "0.0.0.0", 22, "LISTEN", ""), ("tcp", "0.0.0.0", 25, "LISTEN", ""),
                        ("udp", "0.0.0.0", 51820, "CLOSE", ""), ("udp", "10.0.0.5", 40000, "ESTAB", "1.1.1.1:53"),
                        ("udp", "0.0.0.0", 68, "CLOSE", ""), ("tcp", "127.0.0.1", 5432, "LISTEN", ""),
                        ("tcp", "::1", 6379, "LISTEN", ""), ("tcp", "0.0.0.0", 80, "LISTEN", "")])
    s = lab.stubs("u9", ss=L_SS)
    its = items(inbound=[{"port": 80}])
    r = lab.helper(t, p, want(its), stubs=s)
    w5 = [v for v in r.get("verdicts", []) if v["id"] == "R03-W5"]
    expect("u9 listeners: R03-W5 names 25/tcp (master) and 51820/udp only (process names filtered)",
          (ids(r), w5[0]["ports"] if w5 else None), (["R03-W5"], ["25/tcp (master)", "51820/udp (wg-x)"]))
    r = lab.helper(t, p, want(its, closed_ok=["25/tcp", "51820/udp"]), stubs=s)
    n1 = [n for n in r.get("notes", []) if n["id"] == "N03-W1"]
    expect("u9 with firewall_closed_ok: no refusal, N03-W1 lists what closes",
          (ids(r), n1[0]["closing"] if n1 else None), ([], ["25/tcp (master)", "51820/udp (wg-x)"]))

    # u10 forwarding and WireGuard
    t = lab.tree("u10")
    p = lab.proc("u10", [("tcp", "0.0.0.0", 22, "LISTEN", "")], sysvals={"net/ipv4/ip_forward": "1"})
    r = lab.helper(t, p, want(items()))
    expect("u10 ip_forward=1 with DEFAULT_FORWARD_POLICY DROP: R03-W7a", ids(r), ["R03-W7a"])
    t = lab.tree("u10b", net={"wg0": "DEVTYPE=wireguard\nINTERFACE=wg0\n"})
    r = lab.helper(t, p0, want(items()))
    expect("u10 a WireGuard interface: R03-W7b", ids(r), ["R03-W7b"])

    # u11 ufw's kernel settings
    t = lab.tree("u11")
    r = lab.helper(t, p0, want(items()))
    n8 = [n for n in r.get("notes", []) if n["id"] == "N03-W8"]
    expect("u11 stock sysctl.conf on stock live values: no refusal, 4 tightening redirect lines",
          (ids(r), sorted(c["key"] for c in n8[0]["changes"]) if n8 else None),
          ([], sorted(["net/ipv4/conf/all/accept_redirects", "net/ipv4/conf/default/accept_redirects",
                       "net/ipv6/conf/all/accept_redirects", "net/ipv6/conf/default/accept_redirects"])))
    p = lab.proc("u11a", [("tcp", "0.0.0.0", 22, "LISTEN", "")],
                 sysvals={"net/ipv4/conf/all/log_martians": "1"})
    r = lab.helper(t, p, want(items()))
    expect("u11 live log_martians 1, ufw sets 0: R03-W8", ids(r), ["R03-W8"])
    p = lab.proc("u11b", [("tcp", "0.0.0.0", 22, "LISTEN", "")],
                 sysvals={"net/ipv4/icmp_echo_ignore_all": "1"})
    r = lab.helper(t, p, want(items()))
    expect("u11 live icmp_echo_ignore_all 1, ufw sets 0: R03-W8", ids(r), ["R03-W8"])
    t = lab.tree("u11c", sysctl="net/ipv4/conf/all/rp_filter=0\nnet.ipv4.tcp_syncookies=1\n")
    p = lab.proc("u11c", [("tcp", "0.0.0.0", 22, "LISTEN", "")],
                 sysvals={"net/ipv4/conf/all/rp_filter": "1", "net/ipv4/tcp_syncookies": "0"})
    r = lab.helper(t, p, want(items()))
    w8 = [v for v in r.get("verdicts", []) if v["id"] == "R03-W8"]
    expect("u11 rp_filter 1->0 refused, syncookies 0->1 (dot form) listed",
          (ids(r), [c["key"] for c in w8[0]["changes"]] if w8 else None,
           [c["key"] for n in r.get("notes", []) if n["id"] == "N03-W8" for c in n["changes"]]),
          (["R03-W8"], ["net/ipv4/conf/all/rp_filter"], ["net/ipv4/tcp_syncookies"]))
    t = lab.tree("u11d", default={"IPT_SYSCTL": "/etc/sysctl.conf"})
    write(os.path.join(t, "etc/sysctl.conf"), "")
    r = lab.helper(t, p0, want(items()))
    expect("u11 IPT_SYSCTL outside /etc/ufw: R03-W8", ids(r), ["R03-W8"])

    # u12 policies
    t = lab.tree("u12a", default={"DEFAULT_INPUT_POLICY": '"ACCEPT"'})
    r = lab.helper(t, p0, want(items()))
    expect("u12 DEFAULT_INPUT_POLICY ACCEPT: R03-W9a", ids(r), ["R03-W9a"])
    t = lab.tree("u12b", default={"DEFAULT_OUTPUT_POLICY": '"DROP"'})
    r = lab.helper(t, p0, want(items()))
    expect("u12 DEFAULT_OUTPUT_POLICY DROP and egress_lockdown false: R03-W9b", ids(r), ["R03-W9b"])
    t = lab.tree("u12c", default={"MANAGE_BUILTINS": "yes"})
    r = lab.helper(t, p0, want(items()))
    expect("u12 MANAGE_BUILTINS=yes: R03-W9c", ids(r), ["R03-W9c"])

    # u13 IPV6=no on a host with a global IPv6 address; edited before.rules
    t = lab.tree("u13", default={"IPV6": "no"}, edit_before=True, init_exec=True)
    p = lab.proc("u13", [("tcp", "0.0.0.0", 22, "LISTEN", "")], inet6=["2001:db8::10"])
    its = items(office="2001:db8::7")
    r = lab.helper(t, p, want(its))
    expect("u13 IPV6=no + global IPv6: N03-W6; edited before.rules and before.init: N03-W7; v6 office skipped",
          (ids(r), ids(r, "notes"), [s["status"] for s in r.get("items", [])]),
          ([], ["N03-W6", "N03-W7", "N03-W8"], ["skip", "add"]))
    ok, d = apply_and_compare(lab, t, its, r)
    check("u13 IPV6=no: real ufw == expected_after", ok, d)

    # u14 a 0.x office rule behind 'limit 22/tcp' (off ufw): N03-W3
    t = lab.tree("u14")
    lab.ufw(t, "limit", "22/tcp")
    lab.ufw(t, "allow", "from", "203.0.113.7", "to", "any", "port", "22", "proto", "tcp")
    r = lab.helper(t, p0, want(items(office="203.0.113.7")))
    expect("u14 0.x office rule behind the limit rule: covered + N03-W3",
          ([s["status"] for s in r.get("items", [])], ids(r, "notes")), (["covered", "covered"], ["N03-W3", "N03-W8"]))

    # u15 office prepend first, v6 inbound after the v4 rules, egress lockdown
    t = lab.tree("u15")
    lab.ufw(t, "allow", "from", "2001:db8::/32", "to", "any", "port", "8443", "proto", "tcp")
    its = items(office="203.0.113.7/32", inbound=[{"port": 443}, {"port": 5432, "from": "2001:db8:1::5/64"},
                                                    {"port": "6000:6010", "proto": "udp"},
                                                    {"port": 3000, "from": "198.51.100.5/24", "rule": "limit"}],
                egress=True, extra=[(587, "tcp")])
    p = lab.proc("u15", [("tcp", "0.0.0.0", 22, "LISTEN", ""), ("tcp", "2001:db8::10", 8443, "LISTEN", "")])
    r = lab.helper(t, p, want(its, egress=True))
    n1 = [n for n in r.get("notes", []) if n["id"] == "N03-W1"]
    expect("u15 office + v6 + range + limit + egress: no refusal, every item added, 8443 open only to your source",
           (ids(r), sorted({s["status"] for s in r.get("items", [])}), n1[0]["restricted"] if n1 else None),
           ([], ["add"], ["8443/tcp"]))
    p = lab.proc("u15b", [("tcp", "0.0.0.0", 22, "LISTEN", ""), ("tcp", "::", 8443, "LISTEN", "")])
    r2 = lab.helper(t, p, want(its, egress=True))
    expect("u15 a dual-stack [::]:8443 listener: its IPv4 side is not let in, R03-W5", ids(r2), ["R03-W5"])
    ok, d = apply_and_compare(lab, t, its, r, egress_policy=True)
    check("u15 real ufw == expected_after (prepend first, IPv6-only rules last, addresses as ufw prints them)", ok, d)
    check("u15 the office rule is the first rule", (lab.added(t) or [""])[0].startswith("ufw allow from 203.0.113.7 "),
          lab.added(t)[:2])

    # u16 other firewall managers, ufw.service not enabled
    t = lab.tree("u16")
    s = lab.stubs("u16", units={"is-active firewalld.service": "active", "is-enabled ufw.service": "disabled"})
    r = lab.helper(t, p0, want(items()), stubs=s)
    expect("u16 firewalld active and ufw.service disabled: R03-W6a and R03-W6b", ids(r), ["R03-W6a", "R03-W6b"])

    # u17 ufw not installed yet (--no-ufw): package defaults, listener check runs
    t = lab.tree("u17")
    p = lab.proc("u17", [("tcp", "0.0.0.0", 22, "LISTEN", ""), ("tcp", "0.0.0.0", 3000, "LISTEN", "")])
    r = lab.helper(t, p, want(items()), no_ufw=True)
    expect("u17 --no-ufw: no ufw call, 3000/tcp refused (R03-W5), no ufw-file checks",
          (r.get("mode"), ids(r), r.get("ufw_lines")), ("no-ufw", ["R03-W5"], []))

    # u18 the helper refuses an unreadable ufw (R03-W1)
    t = lab.tree("u18")
    os.remove(os.path.join(t, "etc/ufw/user.rules"))
    write(os.path.join(t, "etc/ufw/user.rules"), "garbage\n")
    os.chmod(os.path.join(t, "etc/ufw/user.rules"), 0o000)
    r = lab.helper(t, p0, want(items()))
    os.chmod(os.path.join(t, "etc/ufw/user.rules"), 0o644)
    check("u18 ufw cannot read its rules: R03-W1", "R03-W1" in ids(r), r)

    # u19 comment of yours kept: 'allow 80/tcp comment web' covers inbound 80 (no replace)
    t = lab.tree("u19")
    lab.ufw(t, "limit", "22/tcp")
    lab.ufw(t, "allow", "80/tcp", "comment", "web")
    before = lab.added(t)
    r = lab.helper(t, p0, want(items(inbound=[{"port": 80}])))
    expect("u19 'allow 80/tcp comment web' covers {port: 80}; expected_after unchanged",
          ([s["status"] for s in r.get("items", [])], r.get("expected_after") == before), (["covered", "covered"], True))

    # u20 'limit 80/tcp' wanted over your 'allow 80/tcp' -> R03-W3 (ufw would replace)
    r = lab.helper(t, p0, want(items(inbound=[{"port": 80, "rule": "limit"}])))
    expect("u20 limit wanted over your allow: R03-W3", ids(r), ["R03-W3"])

    # u21 host strings are filtered: braces and control characters never come back
    t = lab.tree("u21")
    lab.ufw(t, "limit", "22/tcp", "comment", "x{{ lookup(pipe) }}")
    r = lab.helper(t, p0, want(items()))
    blob = json.dumps(r)
    check("u21 a comment with braces and a control character comes back filtered",
          "{{" not in blob and "lookup(pipe)" in blob and "\u0007" not in blob, blob[:400])

    # u22 the active canary is not the helper's business: role 03 never runs it
    # there (a2 checks that with Ansible). Here: the helper itself never writes.
    t = lab.tree("u22")
    lab.ufw(t, "limit", "22/tcp")
    snap = {f: open(os.path.join(t, "etc/ufw", f), "rb").read() for f in ("user.rules", "user6.rules", "ufw.conf")}
    snap["default"] = open(os.path.join(t, "etc/default/ufw"), "rb").read()
    lab.helper(t, p0, want(items(inbound=[{"port": 443}], office="203.0.113.7"), egress=True))
    after = {f: open(os.path.join(t, "etc/ufw", f), "rb").read() for f in ("user.rules", "user6.rules", "ufw.conf")}
    after["default"] = open(os.path.join(t, "etc/default/ufw"), "rb").read()
    check("u22 the helper is read-only (ufw's 4 files byte-identical)", snap == after)

    # u23 SSH open through 'allow 22' (any protocol): covered
    t = lab.tree("u23")
    lab.ufw(t, "allow", "22")
    r = lab.helper(t, p0, want(items()))
    expect("u23 'allow 22' (tcp and udp) covers the SSH rule", ([s["status"] for s in r["items"]], ids(r)), (["covered"], []))

    # u24 a range of yours covers an inbound item
    t = lab.tree("u24")
    lab.ufw(t, "limit", "22/tcp")
    lab.ufw(t, "allow", "1000:2000/udp")
    r = lab.helper(t, p0, want(items(inbound=[{"port": 1500, "proto": "udp"}])))
    expect("u24 'allow 1000:2000/udp' covers {port: 1500, proto: udp}", [s["status"] for s in r["items"]],
          ["covered", "covered"])


def ansible_checks(lab, playbook):
    """Role 03's real task files: preflight.yml (vars, ufw-preflight,
    ufw-check, ufw-decide, ufw-plan, the fail2ban part with keep) and
    ufw-add.yml, as the current user against lab trees."""
    tag = os.path.basename(os.path.dirname(os.path.dirname(playbook)))
    stubs = os.path.join(lab.w, "ansible-stubs")
    for inst in ("installed", "missing"):
        write(os.path.join(stubs, inst, "dpkg-query"),
              "#!/bin/sh\n%s" % ("printf 'ii |ufw\\n'\n" if inst == "installed" else "exit 1\n"), 0o755)

    def run(name, t, active, ev, installed=True, proc=None, units=None, ss="", check_mode=False):
        p = proc or lab.proc("a-" + name, [("tcp", "0.0.0.0", 22, "LISTEN", "")])
        s = lab.stubs("a-" + name, units=units, ss=ss)
        base = {"_fw_ufw_argv": [lab.wrapper(t, active)], "_fw_python": sys.executable,
                "_fw_helper_lab_args": ["--root", t, "--proc", p, "--systemctl", os.path.join(s, "systemctl"),
                                        "--ss", os.path.join(s, "ss"), "--ufw", json.dumps([lab.wrapper(t, active)])],
                "ssh_port": 22, "lab_apply": True}
        base.update(ev)
        evf = os.path.join(lab.w, "ev-%s-%s.json" % (tag, name))
        write(evf, json.dumps(base))
        env = dict(os.environ, LC_ALL="C.UTF-8", ANSIBLE_NOCOLOR="1", ANSIBLE_RETRY_FILES_ENABLED="False",
                   ANSIBLE_LOCALHOST_WARNING="False", ANSIBLE_INVENTORY_UNPARSED_WARNING="False",
                   ANSIBLE_ROLES_PATH=lab.a.roles, ANSIBLE_DEPRECATION_WARNINGS="False",
                   PATH=os.path.join(stubs, "installed" if installed else "missing") + ":" + os.environ.get("PATH", ""))
        argv = [playbook, "-i", "localhost,", os.path.join(lab.a.here, "ansible-lab.yml"), "-e", "@" + evf]
        r = subprocess.run(argv + (["--check"] if check_mode else []), capture_output=True, text=True, env=env, cwd=lab.w)
        out = r.stdout + r.stderr
        write(os.path.join(lab.w, "ansible-%s-%s.log" % (tag, name)), out)
        return r.returncode, out

    # a1 fresh tree, firewall_state enabled: preflight plans 3 adds; ufw-add
    # runs them with the real ufw and U7's exact check passes.
    t = lab.tree("a1")
    p = lab.proc("a1", [("tcp", "0.0.0.0", 22, "LISTEN", ""), ("tcp", "0.0.0.0", 443, "LISTEN", ""),
                        ("tcp", "0.0.0.0", 3000, "LISTEN", "")])
    rc, out = run("a1", t, False, {"firewall_state": "enabled", "firewall_inbound": [{"port": 443}, {"port": 80}],
                                   "firewall_closed_ok": ["3000/tcp"], "office_static_ip": "203.0.113.7"}, proc=p)
    expect("a1 %s fresh + enabled: rc 0, U7 passed, the office rule first" % tag,
          (rc, "M03-W2" in out and "FAILED" in out, (lab.added(t) or [""])[0]),
          (0, False, "ufw allow from 203.0.113.7 to any port 22 proto tcp comment 'auto_sec'"), out[-1500:])
    check("a1 %s plan lines: 4 add-rule + firewall-on" % tag,
          out.count("'do': 'add-rule'") + out.count('"do": "add-rule"') >= 4 and "firewall-on" in out, out[-1500:])

    # a2 the canary: ufw ACTIVE with limit 22, allow 80/443: no helper, no ufw write
    t = lab.tree("a2")
    for c in (["limit", "22/tcp"], ["allow", "80/tcp"], ["allow", "443/tcp"]):
        lab.ufw(t, *c)
    before = lab.added(t)
    rc, out = run("a2", t, True, {"firewall_state": "enabled", "firewall_inbound": [{"port": 8443}],
                                  "lab_apply": False})
    expect("a2 %s canary (active): rc 0, no helper run, N03-W2 gives the sudo line, plan []" % tag,
          (rc, "ufw check: ask the turn-on helper" in out, "sudo ufw allow 8443/tcp comment auto_sec" in out,
           "LAB _plan_03=[]" in out, lab.added(t) == before),
          (0, False, True, True, True), out[-1500:])

    # a3 egress_lockdown true on an active ufw that allows outgoing: R03-W13
    rc, out = run("a3", t, True, {"egress_lockdown": True, "lab_apply": False})
    expect("a3 %s egress_lockdown on an active ufw allowing outgoing: R03-W13, rc != 0" % tag,
          (rc != 0, "R03-W13" in out), (True, True), out[-1500:])

    # a4 inactive ufw with keep: N03-W10, nothing
    t = lab.tree("a4")
    rc, out = run("a4", t, False, {"firewall_state": "keep", "lab_apply": False})
    expect("a4 %s off + keep: N03-W10, plan []" % tag, (rc, "N03-W10" in out, "LAB _plan_03=[]" in out),
          (0, True, True), out[-1500:])

    # a5 refusal texts render: R03-W5 with process names, and the variable checks
    t = lab.tree("a5")
    p = lab.proc("a5", [("tcp", "0.0.0.0", 22, "LISTEN", ""), ("tcp", "0.0.0.0", 25, "LISTEN", "")])
    rc, out = run("a5", t, False, {"firewall_state": "enabled", "lab_apply": False}, proc=p, ss=L_SS)
    expect("a5 %s R03-W5 message names '25/tcp (master)'" % tag,
          (rc != 0, "these ports listen now and no rule" in out, "25/tcp (master)" in out), (True, True, True), out[-1500:])
    rc, out = run("a5b", t, False, {"firewall_state": True, "lab_apply": False})
    expect("a5 %s firewall_state: true (YAML boolean) refused" % tag,
          (rc != 0, "not\ntrue/false" in out or "not true/false" in out or "YAML boolean" in out), (True, True), out[-800:])
    rc, out = run("a5c", t, False, {"firewall_inbound": [{"port": 22}, {"port": "9:3", "proto": "tcp"},
                                                         {"port": 80, "from": "0.0.0.0/0"}, {"port": 80, "x": 1}],
                                    "lab_apply": False})
    expect("a5 %s firewall_inbound errors listed (ssh port, bad range, any source, unknown key)" % tag,
          (rc != 0, "is SSH (ssh_port)" in out, "must be A:B" in out, "from must be one" in out, "unknown key" in out),
          (True, True, True, True, True), out[-1500:])
    rc, out = run("a5d", lab.tree("a5d"), False, {"firewall_state": "enabled", "app_type": "node",
                                                  "firewall_inbound": [{"port": 443}], "lab_apply": False})
    expect("a5 %s app_type without 80/tcp in firewall_inbound: R03-W12" % tag,
          (rc != 0, "{ port: 80 }" in out), (True, True), out[-800:])
    rc, out = run("a5e", lab.tree("a5e"), False, {"firewall_state": "enabled", "lab_apply": False}, installed=False)
    expect("a5 %s ufw not installed + enabled: plan 'install ufw; then checks', wants [ufw]" % tag,
          (rc, "install ufw; then checks; then turn ufw on" in out, "LAB _fw_pkg_want=['ufw']" in out),
          (0, True, True), out[-1500:])

    # a6 role 03's ufw.yml in --check: U0-U3 (the helper again, M03-W1, the
    # same decision), nothing added, nothing turned on.
    t = lab.tree("a6")
    before = lab.added(t)
    rc, out = run("a6", t, False, {"firewall_state": "enabled", "firewall_inbound": [{"port": 443}],
                                   "lab_apply": False, "lab_ufw_main": True}, check_mode=True)
    expect("a6 %s ufw.yml in --check: rc 0, M03-W1 passed, U3 prints the commands, no rule added" % tag,
           (rc, "ufw U2 M03-W1" in out and "FAILED" not in out,
            "Check mode: turn ufw on (2 rule(s) to add) on localhost: ufw limit 22/tcp comment auto_sec; "
            "ufw allow 443/tcp comment auto_sec; ufw --force enable." in out, lab.added(t) == before),
           (0, True, True, True), out[-2000:])
    # a7 ufw changed between the preflight and ufw.yml: M03-W1
    t = lab.tree("a7")
    rc, out = run("a7", t, False, {"firewall_state": "enabled", "lab_apply": False, "lab_ufw_main": True,
                                   "lab_touch_between": True}, check_mode=True)
    expect("a7 %s a rule added between the preflight and ufw.yml: M03-W1, rc != 0" % tag,
           (rc != 0, "changed during this run" in out), (True, True), out[-1500:])
    # a8 ufw turned ON between the preflight and ufw.yml (ENABLED=yes, the
    # lab reports active): refused before any ufw command (M03-W1 now
    # compares ufw.conf's ENABLED too; M03-W4 reads ufw status).
    t = lab.tree("a8")
    p8 = lab.proc("a-a8", [("tcp", "0.0.0.0", 22, "LISTEN", "")])
    s8 = lab.stubs("a-a8b")
    act = lab.wrapper(t, True)
    rc, out = run("a8", t, False, {"firewall_state": "enabled", "lab_apply": False, "lab_ufw_main": True,
                                   "lab_turn_on_between": True, "lab_tree": t, "lab_active_argv": [act],
                                   "lab_active_helper_args": ["--root", t, "--proc", p8, "--systemctl",
                                                              os.path.join(s8, "systemctl"), "--ss", os.path.join(s8, "ss"),
                                                              "--ufw", json.dumps([act])]},
                  proc=p8, check_mode=True)
    expect("a8 %s ufw turned on between the preflight and ufw.yml: refused, no command printed" % tag,
           (rc != 0, "changed during this run" in out, "Check mode: turn ufw on" in out, lab.added(t)),
           (True, True, False, []), out[-1500:])


def main():
    ap = argparse.ArgumentParser()
    for k in ("helper", "roles", "src", "pkg", "work", "here", "set"):
        ap.add_argument("--" + k, required=True)
    ap.add_argument("--ansible", action="append", default=[])
    a = ap.parse_args()
    lab = Lab(a)
    print("== ufw-semantics (%s)" % a.set)
    helper_checks(lab)
    for pb in a.ansible:
        ansible_checks(lab, pb)
    print("== %d passed, %d failed" % (len(PASSED), len(FAILED)))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
