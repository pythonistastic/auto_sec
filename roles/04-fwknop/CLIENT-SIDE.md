# Connecting to a fwknop-gated server

**In auto_sec 0.4.0 the SSH port stays visible in high mode.** Role 04
installs and starts fwknopd, but the ufw SSH rule stays in place, so you
do not need to knock yet. Hiding SSH behind a knock returns in a later
release. You can set up the client now, to be ready.

Install client: `apt install fwknop-client` or `brew install fwknop`

Create ~/.fwknoprc. Use your server's `ssh_port` (22 unless you moved
it; see [docs/ssh-port.md](../../docs/ssh-port.md)):

    [example-client]
    ACCESS              tcp/<ssh_port>
    SPA_SERVER          203.0.113.10
    KEY_BASE64          <same key as server>
    HMAC_KEY_BASE64     <same hmac key>
    USE_HMAC            Y
    ALLOW_IP            resolve

Then:

    fwknop -n example-client && ssh -p <ssh_port> <admin account>@203.0.113.10

`<admin account>` is your `ssh_admin_user` (for example `deploy` or
`root`). A knock opens `ssh_port` for your IP for `fwknop_open_seconds`
(default 30). Established sessions stay alive after it closes.
