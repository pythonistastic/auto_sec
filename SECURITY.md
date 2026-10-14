# Security policy

auto_sec is a hardening tool. A flaw in it does not just affect this repository — it
affects every server someone pointed it at. Reports are taken seriously and credited.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.**

Use GitHub's private reporting: **Security → Advisories → Report a vulnerability** on
[this repository](https://github.com/pythonistastic/auto_sec/security/advisories/new).
That channel is private until a fix ships.

Useful things to include, in rough order of value:

- The file and line, and the variable or input involved.
- A concrete malicious value and what it achieves (root execution? file write? lockout?).
- Whether it needs operator-supplied input, or input an attacker can influence from a
  managed server.
- The OS and `ansible-core` version you saw it on.

You will get an acknowledgement within a few days. This is a one-maintainer, early-stage
project, so please don't expect enterprise response times — but security reports go to the
front of the queue.

## What counts as a vulnerability here

In scope, roughly in order of severity:

- **Code execution** — any path where a variable's value becomes part of a command. The
  high-risk sinks are Jinja interpolation into `shell:` or into a `.j2` that renders a
  script, and argv splitting in `command:` that injects an extra flag.
- **Privilege escalation** — anything that lets a lower-privileged user on a managed host
  reach root, especially *through* auto_sec's own scheduled jobs.
- **Backup compromise** — anything that changes who can decrypt a backup, lets a managed
  host destroy or hide backup history, or causes a restore to silently produce the wrong
  data.
- **Lockout** — a change that can leave an operator unable to reach their own server, or
  that writes a config whose effect differs from what it reports.
- **Secret disclosure** — tokens or keys reaching logs, `ps`, world-readable files, or a
  client-facing report.
- **False assurance** — the tool, or the generated client report, claiming a control is
  active when it is not. This is treated as a security bug, not a cosmetic one, because
  the report is relied upon.

Out of scope: findings that require the operator to deliberately attack their own
infrastructure with values only they can set, *unless* the same path can be reached by
data read from a managed host. That distinction matters a lot here — see below.

## A note on trust boundaries

Most variables in `host_vars` are typed by the operator, so a malicious value is
self-inflicted and low-risk. That changes the moment a value is **derived from a managed
server** (a hostname read from a config file, a package name, a domain from an nginx
vhost). Then an attacker with limited access to that server can influence a value that
auto_sec later runs as root.

Therefore: **facts collected from a managed host must never be promoted into variables
automatically.** They may be displayed to the operator; a human types the value. Treat any
report that crosses this boundary as high severity.

Likewise, anything auto_sec *reads* from a host — log lines, process names, file names,
CVE descriptions — is untrusted data, never instructions.

## Supported versions

Pre-1.0: only the latest tag receives fixes. Upgrade before reporting if you can.

| Version | Supported |
|---|---|
| latest tag | ✅ |
| anything older | ❌ |

## Disclosure

Fixes ship in a patch release with the advisory published at the same time, and the
CHANGELOG entry links back to it. If you'd like credit, say so in the report and tell me
how you want to be named.

## Honest limitations

auto_sec is early-stage and does not promise complete security. Known gaps — including
parts that are shipped but not yet validated end-to-end — are tracked openly in
[docs/RETROSPECTIVE.md](docs/RETROSPECTIVE.md). Reading that first may save you a report
about something already known.
