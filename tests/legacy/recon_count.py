"""Count what auto_sec 0.3-0.5's recon detector would see in a strace.

Usage: python3 -I recon_count.py <patterns file> <strace -ff output prefix>...
Reads every <prefix>.<pid> file, takes each successful execve's argv,
joins it with spaces (as the audit EXECVE record gives it), and applies the
detector's rule: the first pattern that matches a command is its
indicator, and only distinct indicators count. Prints the number of
commands and the indicators, then "indicators: <n>".
"""
import glob
import re
import sys


def literal(s, i):
    """Parse a strace C string literal at s[i] == '"'; return (text, next index)."""
    assert s[i] == '"'
    out, i = [], i + 1
    while s[i] != '"':
        if s[i] == "\\":
            nxt = s[i + 1]
            if nxt in "01234567":
                j = i + 1
                while j < i + 4 and s[j] in "01234567":
                    j += 1
                out.append(chr(int(s[i + 1:j], 8)))
                i = j
                continue
            if nxt == "x":
                out.append(chr(int(s[i + 2:i + 4], 16)))
                i += 4
                continue
            out.append({"n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f"}.get(nxt, nxt))
            i += 2
            continue
        out.append(s[i])
        i += 1
    i += 1
    if s.startswith("...", i):
        i += 3
    return "".join(out), i


def argv_of(line):
    k = line.find("execve(")
    if k < 0 or " = 0" not in line[line.rfind(")"):]:
        return None
    _, i = literal(line, k + len("execve("))
    if not line.startswith(", [", i):
        return None
    i += 3
    args = []
    while line[i] == '"':
        a, i = literal(line, i)
        args.append(a)
        if line.startswith(", ", i):
            i += 2
    return args


patterns = [re.compile(p) for p in
            (l.rstrip("\n") for l in open(sys.argv[1]))
            if p and not p.startswith("#")]
cmds = []
for prefix in sys.argv[2:]:
    for f in sorted(glob.glob(prefix + ".*")):
        for line in open(f, errors="replace"):
            a = argv_of(line)
            if a:
                cmds.append(" ".join(a))
hits = []
for c in cmds:
    m = next((p.pattern for p in patterns if p.search(c)), None)
    if m and m not in hits:
        hits.append(m)
print("commands: %d" % len(cmds))
for h in hits:
    print("  indicator %s in: %s" % (h, next(c for c in cmds if re.search(h, c))[:160]))
print("indicators: %d" % len(hits))
