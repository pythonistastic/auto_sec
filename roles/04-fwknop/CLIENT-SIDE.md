# Connecting to a fwknop-gated server

Install client: `apt install fwknop-client` or `brew install fwknop`

Create ~/.fwknoprc:

    [example-client]
    ACCESS              tcp/22
    SPA_SERVER          203.0.113.10
    KEY_BASE64          <same key as server>
    HMAC_KEY_BASE64     <same hmac key>
    USE_HMAC            Y
    ALLOW_IP            resolve

Then:

    fwknop -n example-client && ssh deploy@203.0.113.10

Port 22 opens for your IP for 30 seconds, established sessions stay alive
after it closes.
