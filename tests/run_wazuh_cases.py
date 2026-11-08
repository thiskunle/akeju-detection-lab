# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Detection Lab, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""Feed sample logs to the running Wazuh manager and check which rules fire. Needs Docker."""
import pathlib
import re
import subprocess
import sys
import time

import yaml

CONTAINER = "akeju-lab-manager"
LOGTEST = "/var/ossec/bin/wazuh-logtest"
CASES = yaml.safe_load((pathlib.Path(__file__).parent / "wazuh_cases.yml").read_text(encoding="utf-8"))


def docker(*args, stdin=None, timeout=60):
    return subprocess.run(["docker", "exec", "-i", CONTAINER, *args], input=stdin, capture_output=True, text=True, timeout=timeout)


def wait_until_ready(limit=240):
    deadline = time.time() + limit
    while time.time() < deadline:
        status = docker("/var/ossec/bin/wazuh-control", "status")
        if "wazuh-analysisd is running" in status.stdout:
            probe = docker(LOGTEST, stdin="Nov  8 10:00:01 host sshd[1]: test\n")
            if "Phase 1" in probe.stdout + probe.stderr:
                return
        time.sleep(5)
    sys.exit("Wazuh did not become ready.")


def fired(lines):
    result = docker(LOGTEST, stdin="\n".join(lines) + "\n")
    return set(re.findall(r"id: '(\d+)'", result.stdout + result.stderr))


def main():
    wait_until_ready()
    failures = 0
    for case in CASES:
        lines = case["lines"] * case.get("repeat", 1)
        ids = fired(lines)
        ok = (not case.get("expect") or case["expect"] in ids) and not (set(case.get("reject", [])) & ids)
        print(f"{'PASS' if ok else 'FAIL'}  {case['name']}  rules fired: {sorted(ids)}")
        failures += not ok
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
