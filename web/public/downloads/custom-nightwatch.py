#!/usr/bin/env python3
"""Wazuh -> Nightwatch forwarder (Wazuh "custom integration").

Wazuh's integratord runs this once per alert that matches the <integration> block in
ossec.conf, with three arguments:
    argv[1]  path to a file holding the alert JSON
    argv[2]  <api_key>   -> the site's Nightwatch ingest key (nwk_...)
    argv[3]  <hook_url>  -> https://<nightwatch>/api/v1/ingest/wazuh

It POSTs the alert as-is. Nightwatch decides the organization from the key alone.
Standard library only, so it runs on Wazuh's bundled Python with nothing to install.

Install and config: see README.md in this folder.
Status: tested by running it by hand against a local Nightwatch. Not yet run by a real
Wazuh manager's integratord; check /var/ossec/logs/integrations.log on the first run.
"""

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

LOG = "/var/ossec/logs/integrations.log"


def log(msg: str) -> None:
    line = f"custom-nightwatch: {msg}\n"
    try:
        with open(LOG, "a") as f:
            f.write(line)
    except OSError:
        sys.stderr.write(line)


def main() -> int:
    if len(sys.argv) < 4:
        log("usage: custom-nightwatch <alert_file> <api_key> <hook_url>")
        return 1
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]

    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except (OSError, ValueError) as e:
        log(f"could not read alert file {alert_file}: {e}")
        return 1

    context = None
    if os.environ.get("NIGHTWATCH_TLS_INSECURE") == "true":  # lab only: self-signed Nightwatch cert
        context = ssl._create_unverified_context()

    req = urllib.request.Request(
        hook_url,
        data=json.dumps(alert).encode("utf-8"),
        method="POST",
        headers={"content-type": "application/json", "authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=context) as res:
            if res.status != 200:
                log(f"alert {alert.get('id')} -> HTTP {res.status}")
                return 1
    except urllib.error.HTTPError as e:
        log(f"alert {alert.get('id')} -> HTTP {e.code}: {e.read()[:200]!r}")
        return 1
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log(f"alert {alert.get('id')} -> could not reach Nightwatch: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
