# Replay samples

| File | What it is |
| --- | --- |
| `clinic-attack.json` | Hand-made clinic scenario: password guessing, sign-in, PowerShell download, plus a username written to trick the AI. |
| `splunk-password-spray.json` | Real Windows Security events from a password spray (T1110.003): 50 accounts tried from 10.0.1.15 in 50 seconds. |
| `splunk-clop-ransomware.json` | Real Sysmon events from the Clop ransomware: shadow copies deleted, `clop.exe` started, ransom notes written, files renamed to `.Clop`. |

The two `splunk-*` files are converted from Splunk's public attack data
([github.com/splunk/attack_data](https://github.com/splunk/attack_data), Apache License 2.0, Copyright Splunk Inc.):

- `datasets/attack_techniques/T1110.003/purplesharp_remote_spray_xml/windows-security.log`
- `datasets/malware/clop/clop_a/windows-sysmon.log`

Field values (users, IP addresses, commands, hashes, file names, event IDs) are unchanged from the source events.
Machine names are renamed to clinic-style names (`OFFICE-SERVER`, `FILESERVER`), and the summary alerts that stand in
for Wazuh correlation rules use the custom rule range (100000+).

Replay one:

```bash
node tools/replay/replay.mjs tools/replay/samples/splunk-clop-ransomware.json --url http://localhost:3000 --key nwk_dev_northfield_0001 --fresh --gap 1500
```


## Hand-written scenarios (`scenario-*.json`)

These are written by us, not captured from a real network. They follow the Windows Security
and Sysmon event ids, field names, Wazuh rule levels and MITRE ids each attack produces. Each
uses its own machine name so it becomes exactly one incident.

| File | Attack | MITRE |
| --- | --- | --- |
| scenario-phishing-macro.json | Word macro starts hidden PowerShell, downloads and runs a payload | T1566.001, T1059.001 |
| scenario-lsass-dump.json | LSASS memory dumped with comsvcs.dll (credential theft) | T1003.001 |
| scenario-rdp-bruteforce.json | Remote Desktop password guessing from the internet, then success | T1110.001, T1021.001 |
| scenario-scheduled-task.json | Hidden PowerShell scheduled task and Run key (persistence) | T1053.005, T1547.001 |
| scenario-rogue-admin.json | New account created at 3 a.m. and added to Administrators | T1136.001, T1098 |
| scenario-records-exfil.json | rclone copies the patient records folder to cloud storage | T1567.002 |
| scenario-backup-false-positive.json | Backup software deleting old shadow copies (should be closed as a false positive) | T1490 |

Replay one:

    node tools/replay/replay.mjs tools/replay/samples/scenario-lsass-dump.json --url http://localhost:3000 --key <ingest key> --fresh --gap 300
