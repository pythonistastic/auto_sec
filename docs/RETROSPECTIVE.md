# auto_sec — Development Retrospective

An honest account of what **didn't** work, what remains **unsolved**, and
what has been **claimed but not yet proven**. auto_sec is early-stage; this
document exists so anyone evaluating it can see the gaps as clearly as the
features. If you only read the marketing, read this too.

Last updated: 2026-07 (after the first real-hardware test on Ubuntu 22.04).

---

## 1. The headline failure: the SSH login-pattern watcher

This was the **original core idea** — "watch what a user does right after they
log in; if they don't perform the expected pattern, treat it as a breach." It
is the one feature we **could not make reliable**, and it ships **disabled by
default** (`ssh_pattern_watcher_enabled: false`).

**Why it failed, specifically:**

- The design is *react-to-login-then-inspect*: it sees `Accepted publickey` in
  the auth log, then tries to work out what that session is doing. That is
  fundamentally racy.
- **It cannot reliably distinguish an interactive human from automation.**
  `ssh host "sudo ..."` — exactly what Ansible, CI, and git hooks do — kept
  triggering false positives.
- We tried **three** ways to detect "interactive human," all defeated on real
  hardware:
  1. *Has a TTY?* → defeated by `sudo`'s `use_pty` (an Ubuntu default), which
     gives non-interactive automation a pty.
  2. *Is the session leader a login shell (`-bash`)?* → the logind session
     leader is always `sshd`, never the shell.
  3. *Is there a login shell anywhere in the session?* → still false-positived
     under concurrent logins.
- **Session misattribution:** with several SSH sessions from the same IP at
  once, the watcher matches a login to the wrong session (it only has user + IP
  to go on), so an automation login can inherit an interactive session's
  verdict.

**Status: unsolved.** We kept it in the tree as an experimental, opt-in
component and let the reverse-shell and recon detectors carry the product. The
recon-burst detector delivers the *spirit* of the original idea ("catch them
looking around") far more robustly.

**Deeper truth:** even conceptually this was a shared static secret — a
tripwire, not behavioural analysis. The known critiques (doesn't scale across
many users, evadable depending on shell/channel type, users forget the pattern)
are all valid and none were fully answered.

---

## 2. Large parts of the product were never tested end-to-end

Validation covered **one** OS (Ubuntu 22.04) and only exercised **5 of the 10
roles** live (base, ssh-hardening, firewall, detection, watcher). The following
were **never run against real hardware**:

- **Backups (role 07)** — no Backblaze B2 account was used. The no-delete-key
  design, client-side encryption, upload, and the **monthly restore-test
  playbook** are all **unproven in practice**. This is the part most people
  argue matters most.
- **fwknop / Single Packet Authorization (role 04)** — the "invisible SSH port"
  was never tested; its lockout risk is real and unverified.
- **App runtime + TLS (role 05)** — nginx, certbot, PM2/Docker never ran (no
  domain pointed at the box).
- **Database (role 06)** — Postgres/MySQL least-privilege setup untested.
- **Client report (role 10)** and **egress lockdown** — untested live.
- **Telegram alerting** — the entire test ran with **no bot token**, so
  `notify()` was a no-op. **The alert-delivery path has never actually
  delivered an alert.** We proved detectors *write incident files*; we never
  proved a human gets pinged.
- **`active` mode** — every test ran in `alert` mode. The kill-session /
  block-IP / terminate-process response has **never been fired for real**, and
  it has known sharp edges (e.g. could block loopback, or kill the wrong
  process/session).

> **"Supported: Ubuntu 22.04/24.04, Debian 12" is currently a claim, not a
> tested fact** — only 22.04 was validated.

---

## 3. Environmental fragility we found

Live testing surfaced bugs no linter would catch — good that we found them, but
notable that this many appeared on the **very first** real box:

- `ausearch` **hung** on the VPS, silently starving detectors.
  *Fixed:* read the audit log directly instead of shelling out to `ausearch`.
- auditd **did not load its rules** on `systemctl restart` (systemd refuses to
  signal auditd on Ubuntu). *Fixed:* run `augenrules --load`.
- The reverse-shell scanner **false-positived on our own journald sockets**
  (systemd wires a service's stdio to a UNIX socket). *Fixed:* require an
  established TCP peer.

All fixed — but the lesson stands: **budget/cloud VPS environments vary a lot,
and we have seen exactly one.** Expect more surprises on other distros/hosts.
Confidence should read as "works on the box we tried," not "works everywhere."

---

## 4. Inherent limits (not bugs — these remain by design)

- **It does not prevent initial access.** App-layer exploits (e.g. the July
  2026 Hugging Face breach: a malicious dataset → code execution) are exactly
  the class of thing auto_sec cannot stop. It is detection-*after*-entry.
- **The detectors are heuristics and are evadable.** An attacker who moves
  slowly, avoids spawning shells, and tunnels C2 over 443 gets past all of them.
  They raise cost and noise; they do not guarantee anything.
- **Production false-positive rates are unknown.** The recon detector's
  thresholds/patterns were never tuned against real admin behaviour over time.
- **No scale story.** Per-server secret patterns and single-admin assumptions
  do not fit teams or fleets. This is a 1–5 admin tool.

---

## 5. Root-cause themes

1. **We tested late.** Everything looked great while it only had to *lint and
   compile*. The first real VPS invalidated a core feature and exposed three
   environmental bugs within an hour. Real-hardware testing should have come
   earlier and covered more roles.
2. **One clever idea (the pattern watcher) absorbed disproportionate design
   effort** relative to its payoff — and still lost. The robust value turned out
   to be in the "boring" detectors.
3. **The demo path was narrow.** We validated the detection story and skipped
   the backup / TLS / alerting stories — arguably the more important ones for a
   real user.

---

## 6. Honest status snapshot

| Area | Status |
|------|--------|
| Base hardening, SSH lockdown, firewall, auditd tripwires | Validated on Ubuntu 22.04 |
| Reverse-shell detector | Validated (fires, captures evidence) |
| Recon-burst detector | Validated (fires, captures evidence) |
| Wizard / onboarding, CI, docs | Working |
| Backups + restore-test | **Shipped, never run for real** |
| fwknop (SPA) | **Shipped, never tested** |
| App/DB/TLS roles (05/06) | **Shipped, never tested** |
| Telegram alert delivery | **Never actually delivered an alert** |
| `active` response mode | **Never fired for real** |
| Non-Ubuntu-22.04 targets | **Claimed, unverified** |
| SSH login-pattern watcher | **Failed; off by default** |

---

## 7. Open problems (good "help wanted" issues)

1. Reliable interactive-vs-automation **session attribution** for SSH logins
   (the unsolved watcher problem).
2. End-to-end **backup + restore** validation, ideally in CI with a mock or real
   B2 bucket.
3. Proving the **alert path** (Telegram) actually delivers.
4. Testing **`active` mode** safely and hardening its edge cases (never block
   loopback; never kill your own deploy session).
5. **Multi-distro** validation (Ubuntu 24.04, Debian 12, RHEL family).
6. Measuring and tuning the recon detector's **false-positive rate** against
   real workloads.

---

*Contributions that close any of these — especially with a reproducible test —
are exactly what this project needs. See [CONTRIBUTING.md](../CONTRIBUTING.md).*
