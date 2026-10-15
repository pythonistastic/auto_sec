"""What unattended-upgrades itself reads from an apt configuration.

Loads the unattended-upgrade script of one release (unpacked from its
pinned .deb) as a module and asks its own functions, with the apt
configuration that $APT_CONFIG selects:

  APT_CONFIG=<lab>/apt.conf python3 -I uu_eval.py <unattended-upgrade> \
      <distro_id> <codename> <release-dir> <release-prefix> [package...]

<release-dir>/<release-prefix>-*.txt are Release headers (Origin, Label,
Suite, Codename) of real archives. Output, one "key value" line each:
  periodic <Update-Package-Lists> <Unattended-Upgrade> <Enable>
  origin <pattern>                 (get_allowed_origins(), substituted)
  archive <file> YES|no            (match_whitelist_string on that header)
  reboot True|False <time> <with-users>
  remove_unused True|False
  blacklist <entry>
  excluded <package> True|False    (is_pkgname_in_blacklist)
Needs python3-apt and python3-distro-info (the script imports both).
"""
import glob
import importlib.machinery
import importlib.util
import logging
import os
import sys
import types

sys.dont_write_bytecode = True
script, distro_id, codename, reldir, prefix = sys.argv[1:6]
packages = sys.argv[6:]

loader = importlib.machinery.SourceFileLoader("autosec_uu", script)
uu = importlib.util.module_from_spec(importlib.util.spec_from_loader("autosec_uu", loader))
loader.exec_module(uu)
import apt_pkg  # noqa: E402  (initialised by the script's own "import apt")

logging.disable(logging.CRITICAL)
uu.DISTRO_ID = distro_id
uu.DISTRO_CODENAME = codename
c = apt_pkg.config

print("periodic", c.find("APT::Periodic::Update-Package-Lists", "-"),
      c.find("APT::Periodic::Unattended-Upgrade", "-"), c.find("APT::Periodic::Enable", "-"))
allowed = uu.get_allowed_origins()
for o in allowed:
    print("origin", o)
for path in sorted(glob.glob(os.path.join(reldir, prefix + "-*.txt"))):
    with open(path, encoding="ascii") as f:
        h = dict(line.split(": ", 1) for line in f.read().splitlines() if ": " in line)
    origin = types.SimpleNamespace(origin=h.get("Origin", ""), label=h.get("Label", ""),
                                   archive=h.get("Suite", ""), codename=h.get("Codename", ""),
                                   component="main", site="archive.example")
    ok = any(uu.match_whitelist_string(w, origin) for w in allowed)
    print("archive", os.path.basename(path)[:-4], "YES" if ok else "no")
print("reboot", c.find_b("Unattended-Upgrade::Automatic-Reboot", False),
      c.find("Unattended-Upgrade::Automatic-Reboot-Time", "now"),
      c.find_b("Unattended-Upgrade::Automatic-Reboot-WithUsers", True))
print("remove_unused", c.find_b("Unattended-Upgrade::Remove-Unused-Dependencies", False))
blacklist = c.value_list("Unattended-Upgrade::Package-Blacklist")
for b in blacklist:
    print("blacklist", b)
for p in packages:
    print("excluded", p, uu.is_pkgname_in_blacklist(p, blacklist))
