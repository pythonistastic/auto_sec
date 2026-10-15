# Moving the SSH port by hand

auto_sec never moves the SSH port. `ssh_port` means "the port sshd
already listens on". The run checks it and stops if it is wrong. It never
writes `Port` or `ListenAddress`, and it never touches `ssh.socket`.

This page shows how to move the port yourself, safely. The idea is
simple: listen on **both** ports first, test the new one, and only then
close the old one.

## Why auto_sec does not do it

On Ubuntu 24.04 and later, sshd is started by `ssh.socket`. The port is
read by a systemd generator, and only at boot or at `systemctl
daemon-reload`. A port change written to the config can wait unseen until
the next reboot or the next openssh-server update, and then switch ports
by surprise, while the firewall still opens only the old one. That was
issue #5. Moving the port by hand, with a test in between, avoids it.

## Before you start

- Keep your current SSH session open the whole time. Open a second one
  too. Existing sessions normally survive the steps below.
- Have your provider's web console (VNC) ready, in case something goes
  wrong.
- If your provider has its own firewall (a "security group" or "cloud
  firewall"), open the new port there first.
- Check that no auto_sec change is pending:
  `sudo auto-sec-ssh-guard status` should report that nothing is
  pending (the command exists only after auto_sec 0.4.0 has run on the
  server).
- In the examples, the new port is `2222`. Use your own number.

## Step 1: open the new port in ufw

```bash
sudo ufw limit 2222/tcp
```

`limit` is what auto_sec uses for SSH: it allows the port, but slows down
an address that opens too many connections at once. Leave the rule for
the old port in place for now.

## Step 2: make sshd listen on both ports

First, see which `Port` lines exist today:

```bash
sudo grep -rn '^[[:space:]]*Port' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
```

sshd adds up every `Port` line it finds. When there is no `Port` line at
all, it uses 22.

- **No `Port` line found:** the new file needs both ports.

  ```bash
  printf 'Port 22\nPort 2222\n' | sudo tee /etc/ssh/sshd_config.d/10-port.conf
  ```

- **A `Port 22` line already exists:** add only the new port.

  ```bash
  printf 'Port 2222\n' | sudo tee /etc/ssh/sshd_config.d/10-port.conf
  ```

This needs the `Include /etc/ssh/sshd_config.d/*.conf` line in
`/etc/ssh/sshd_config`. Stock Ubuntu and Debian have it, and auto_sec
0.4.0 refuses to run without it.

Check the result. You should see both ports, and no error:

```bash
sudo sshd -t && sudo sshd -T | grep '^port '
```

## Step 3: load it

Find out how sshd is started:

```bash
systemctl is-active ssh.socket
```

- **`active` (Ubuntu 24.04 and later):**

  ```bash
  sudo sshd -t && sudo systemctl daemon-reload && sudo systemctl restart ssh.socket
  ```

  The `daemon-reload` makes the generator read the new ports. The restart
  makes `ssh.socket` listen on them.

- **`inactive` (Ubuntu 22.04, Debian 12 and 13, by default):**

  ```bash
  sudo sshd -t && sudo systemctl restart ssh
  ```

Rare case: `ssh.socket` is active on a release older than Ubuntu 24.04.
Then the ports come from the socket unit, not from sshd_config. This
guide does not cover that case.

Check that both ports are listening:

```bash
sudo ss -tlnp | grep -E ':(22|2222)\b'
```

Do not stop after writing the file. If a change is on disk but not
loaded, the next auto_sec run stops on purpose: it sees files that sshd
has not loaded yet.

## Step 4: test the new port

From a **new** terminal on your own computer:

```bash
ssh -p 2222 youruser@your.server.ip
```

Also check that port 22 still works. Do not go on until the new port
works.

## Step 5: tell auto_sec

Set the new port in two places:

- `host_vars/<server>.yml`: `ssh_port: 2222`
- `inventory/<server>.yml`: `ansible_port: 2222`

Both are needed. The run checks that Ansible really arrived on
`ssh_port`.

Then run only the SSH and firewall parts:

```bash
ansible-playbook -i inventory site.yml -l <server> --tags ssh,firewall
```

This makes the fail2ban `sshd` jail watch the new port, and keeps the
ufw `limit` rule for it. Until this run, fail2ban still blocks only the
old port. In high mode, run with `--tags ssh,firewall,fwknop` instead,
so fwknop's `access.conf` uses the new port too.

Careful: the firewall part still rewrites `/etc/fail2ban/jail.local`
(issue #2). If you tuned that file by hand, run only `--tags ssh`, and
change `port =` in the `[sshd]` section of `jail.local` yourself.

## Step 6: later, close the old port

Wait until every tool you use (VS Code, scripts, CI) uses the new port.
Then remove port 22 the same way:

1. Remove `Port 22` from `10-port.conf`. If the main `sshd_config` has
   its own `Port 22` line, remove that line too.
2. Check: `sudo sshd -t && sudo sshd -T | grep '^port '` shows only the
   new port.
3. Load it, exactly as in step 3.
4. Test `ssh -p 2222 ...` from a new terminal.
5. Only now remove the old firewall rule: `sudo ufw delete limit 22/tcp`.

auto_sec never removes the old ufw rule by itself.

## If something goes wrong

- The new port does not answer: check the provider firewall, then
  `sudo ufw status`, then `sudo ss -tlnp`.
- You are locked out: use the provider's web console. Delete
  `/etc/ssh/sshd_config.d/10-port.conf` and load again (step 3).
