# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Detection Lab, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""Compile each Sigma rule and run it on attack and benign events in a real SQL engine."""
import pathlib
import re
import sqlite3
import uuid

import pytest
import yaml
from sigma.backends.sqlite import sqlite as sigma_sqlite
from sigma.collection import SigmaCollection

ROOT = pathlib.Path(__file__).parents[1]
RULES = sorted((ROOT / "rules" / "sigma").glob("*.yml"))
EVENTS = yaml.safe_load((ROOT / "tests" / "events.yml").read_text(encoding="utf-8"))
COLUMNS = ["Image", "CommandLine", "TargetImage", "GrantedAccess", "SourceImage"]


def query(rule_path):
    collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    return sigma_sqlite.sqliteBackend().convert(collection)[0]


def matches(rule_path, event):
    db = sqlite3.connect(":memory:")
    db.execute(f"CREATE TABLE logs ({', '.join(COLUMNS)})")
    db.execute(f"INSERT INTO logs VALUES ({', '.join('?' * len(COLUMNS))})", [event.get(c, "") for c in COLUMNS])
    return len(db.execute(query(rule_path)).fetchall()) == 1


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.stem)
def test_rule_metadata(rule):
    data = yaml.safe_load(rule.read_text(encoding="utf-8"))
    assert data["author"] == "Adekunle Akeju"
    uuid.UUID(data["id"])
    assert any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in data["tags"]), "needs an ATT&CK technique"
    assert data["falsepositives"] and data["level"]


def test_rule_ids_are_unique():
    ids = [yaml.safe_load(r.read_text(encoding="utf-8"))["id"] for r in RULES]
    assert len(ids) == len(set(ids))


def test_every_rule_has_test_events():
    assert {r.stem for r in RULES} == set(EVENTS)
    assert all(v["attack"] and v["benign"] for v in EVENTS.values())


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.stem)
def test_rule_fires_on_attack_events(rule):
    for event in EVENTS[rule.stem]["attack"]:
        assert matches(rule, event), event


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.stem)
def test_rule_stays_quiet_on_benign_events(rule):
    for event in EVENTS[rule.stem]["benign"]:
        assert not matches(rule, event), event
