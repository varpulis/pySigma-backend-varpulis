"""Route the APT29 lines the way a log shipper would: one event type per
Windows channel. Sysmon lines are left alone (the engine types them by
EventID), and every line gets its line number `_n`, so an alert can be traced
back to the event that raised it."""

import json
import sys

# The event type the backend reads for each Sigma `service`.
CHANNEL_TYPES = {
    "security": "WindowsSecurity",
    "system": "WindowsSystem",
    "microsoft-windows-powershell/operational": "WindowsPowershell",
    "windows powershell": "WindowsPowershellClassic",
    "microsoft-windows-wmi-activity/operational": "WindowsWmi",
    "microsoft-windows-windows firewall with advanced security/firewall": "WindowsFirewallAs",
    "microsoft-windows-terminalservices-localsessionmanager/operational": "WindowsTerminalservicesLocalsessionmanager",
    "microsoft-windows-terminalservices-remoteconnectionmanager/operational": "WindowsTerminalservicesRemoteconnectionmanager",
    "microsoft-windows-bits-client/operational": "WindowsBitsClient",
}

src, dst = sys.argv[1], sys.argv[2]
with open(src) as f, open(dst, "w") as out:
    n = 0
    for line in f:
        if not line.strip():
            continue
        event = json.loads(line)
        channel = (event.get("Channel") or "").lower()
        if "sysmon" not in channel:
            event["type"] = CHANNEL_TYPES[channel]
        event["_n"] = n
        out.write(json.dumps(event, separators=(",", ":")) + "\n")
        n += 1
print(f"{n} events", file=sys.stderr)
