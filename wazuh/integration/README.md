# Wazuh → Nightwatch forwarder

Sends each Wazuh alert to Nightwatch's ingest endpoint as it happens. This is the live
replacement for `web/tools/replay/replay.mjs`, which only replays saved alerts.

```
Kali (attacker) ──► victim VM (Wazuh agent) ──► Wazuh manager ──► custom-nightwatch ──► Nightwatch /api/v1/ingest/wazuh
```

## Install (on the Wazuh manager)

```bash
sudo cp custom-nightwatch.py /var/ossec/integrations/custom-nightwatch.py
# Wazuh launches integrations through a small shell wrapper. Reuse the one that ships with Wazuh:
sudo cp /var/ossec/integrations/slack /var/ossec/integrations/custom-nightwatch
sudo chown root:wazuh /var/ossec/integrations/custom-nightwatch*
sudo chmod 750 /var/ossec/integrations/custom-nightwatch*
```

Add to `/var/ossec/etc/ossec.conf` inside `<ossec_config>`:

```xml
<integration>
  <name>custom-nightwatch</name>
  <hook_url>http://NIGHTWATCH_HOST:3000/api/v1/ingest/wazuh</hook_url>
  <api_key>nwk_PASTE_THE_SITE_INGEST_KEY</api_key>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

- `api_key` is the ingest key shown once when the organization registers (or after
  Settings → Sites → rotate key). It decides which client the alerts belong to.
- `level` 3 sends low-level events too. Nightwatch stores them as context and only opens
  incidents at level 7+ (`INGEST_MIN_LEVEL`). Raise it if the volume is too high.

Then `sudo systemctl restart wazuh-manager` and watch `/var/ossec/logs/integrations.log`.

## Test without Wazuh

```bash
python3 custom-nightwatch.py alert.json nwk_dev_northfield_0001 http://localhost:3000/api/v1/ingest/wazuh
```

`alert.json` is one alert object, e.g. the first item of `web/tools/replay/samples/cityhall-attack.json`.
