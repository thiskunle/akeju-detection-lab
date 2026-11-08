# akeju-detection-lab

**Created by Adekunle Akeju, founder of GramByte Technologies Inc.**

Detection-as-code: threat detections mapped to MITRE ATT&CK, with automated tests for both catching the attack and staying quiet on normal activity.

| Part | What it is | How it is tested |
|---|---|---|
| `rules/sigma/` | 10 Sigma rules for Windows and Linux | Compiled to SQL and run on attack and benign events |
| `wazuh/local_rules.xml` | 5 Wazuh rules with ATT&CK IDs | Fed to a real Wazuh manager with `wazuh-logtest` |
| `docs/atomic-red-team.md` | How to validate with real techniques in a VM | Results are recorded there |

## Coverage

| Technique | Name | Sigma | Wazuh |
|---|---|---|---|
| T1059.001 | PowerShell | Yes | |
| T1059.004 | Unix shell | Yes | Yes |
| T1105 | Ingress tool transfer | Yes | |
| T1053.005 | Scheduled task | Yes | |
| T1490 | Inhibit system recovery | Yes | |
| T1098 | Account manipulation | Yes | |
| T1685.005 | Clear Windows event logs | Yes | |
| T1003.001 | LSASS memory | Yes | |
| T1003.008 | /etc/shadow | Yes | Yes |
| T1136.001 | Create local account | Yes | Yes |
| T1548.003 | Sudo and sudo caching | | Yes |
| T1110.001 | Password guessing | | Yes |

## Run the tests

```
pip install -r requirements.txt
pytest

docker compose up -d
python tests/run_wazuh_cases.py
```

The compose file starts the Wazuh manager only, which is all rule testing needs. For the dashboard, use Wazuh's official single-node Docker deployment and copy `wazuh/local_rules.xml` to `/var/ossec/etc/rules/`.

## Limits

These rules are starting points and need tuning for your environment. The test events are written by hand. Live technique runs are tracked in [docs/atomic-red-team.md](docs/atomic-red-team.md).

## License and credit

AGPL-3.0-or-later, with an attribution requirement. See [NOTICE.md](NOTICE.md). Copyright (c) 2026 Adekunle Akeju.
