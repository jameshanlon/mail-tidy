# mail-tidy

Tools for tidying a Proton Mail mailbox through Proton Mail Bridge.

## Read-only gate

`imap_gate.py` holds the Bridge credentials and exposes a loopback IMAP port
that only permits commands which cannot change the mailbox. Run it in its own
terminal:

    export BRIDGE_USER='<bridge username>' BRIDGE_PASS='<bridge password>'
    export GATE_PASS='<any password for gate clients>'
    python3 imap_gate.py

If `GATE_PASS` is unset, the gate generates one and logs it at startup.
Then point tools at the gate with the gate password:

    BRIDGE_PORT=1144 BRIDGE_STARTTLS=0 BRIDGE_USER=x BRIDGE_PASS="$GATE_PASS" \
        python3 sender_report.py

## Tests

    python3 -m unittest
