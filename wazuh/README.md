# Layer 1: Wazuh (detection + response)

Wazuh collects logs from the clinic's machines, runs detection rules, and blocks IPs when the website tells it to.

## What lives here

| Path | What |
|---|---|
| `integration/` | `custom-nightwatch.py`: forwards every alert to the website. Install steps in its README |
| (add) `ossec.conf` snippets | The `<integration>` block and any custom rules you write |
| (add) `lab.md` | Your VM setup: names, IPs, which snapshot to restore |

## Lab (from the whiteboard)

```
Mac (Wazuh manager / server)
  |
OpenWrt router  (lab network, isolated)
  |-- Ubuntu Server   victim: "file server", Wazuh agent, SSH on
  |-- Windows 11      victim: "front desk PC", Wazuh agent + Sysmon
  '-- Kali            attacker
```

- The laptop running the website (`web/`) and the agents (`agents/`) also joins this router, so Wazuh can reach the website on port 3000 and the website can reach the Wazuh API on 55000.
- VMs must be **bridged** to the router's network (not NAT), so each one gets its own IP. Kali needs its own IP or the block would hit the wrong machine.
- Wazuh doesn't install natively on macOS. Run the manager in Docker (`wazuh-docker` single-node) or an Ubuntu VM on the Mac.
- Take a snapshot of every victim VM before each attack so you can roll back.

## What this layer owes the other two

From [`../docs/INTERFACES.md`](../docs/INTERFACES.md):

- Send alerts to the website in Wazuh's own JSON format (the forwarder does this).
- Give every agent a clear, stable name (`FRONTDESK-PC`, `FILESERVER`). The website groups incidents by it.
- Keep active response enabled on the agents, and give the website a Wazuh API user (port 55000) so it can block IPs.
- Tell the web layer the manager's IP and API login; put the website's address and ingest key in `ossec.conf`.
