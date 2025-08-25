import json
import os
from datetime import datetime
from app import db
from app.models import MitreTactic, MitreTechnique

# Mapping kill_chain phase names to standard tactic IDs
PHASE_NAME_TO_ID = {
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command-and-control": "TA0011",
    "impact": "TA0040",
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
}

MITRE_JSON_PATH = os.path.join(os.path.dirname(__file__), "data", "enterprise-attack.json")


def load_mitre_data():
    print("[INFO] Loading MITRE ATT&CK data...")
    with open(MITRE_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    skipped_count = 0

    # First, load all tactics
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic" or obj.get("type") == "attack-pattern":
            # Skip techniques for now
            continue

        if obj.get("type") == "x-mitre-tactic":
            tactic_id = obj.get("id")
            if not tactic_id:
                continue

            tactic = MitreTactic(
                tactic_id=tactic_id,
                name=obj.get("name"),
                description=obj.get("description", ""),
                url=obj.get("external_references", [{}])[0].get("url"),
                deprecated=obj.get("x_mitre_deprecated", False),
                platforms=",".join(obj.get("x_mitre_platforms", [])) if obj.get("x_mitre_platforms") else None,
                last_updated=datetime.utcnow(),
                source="local",
                mitre_version=obj.get("x_mitre_version", "1.0"),
            )
            try:
                db.session.merge(tactic)
                db.session.commit()
                print(f"[TACTIC] id={tactic_id}, name={tactic.name}")
            except Exception as e:
                db.session.rollback()
                print(f"[ERROR] Failed to insert tactic {tactic_id}: {e}")

    # Then, load techniques
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        technique_id = obj.get("id")
        name = obj.get("name")
        description = obj.get("description", "")
        url = obj.get("external_references", [{}])[0].get("url")
        deprecated = obj.get("x_mitre_deprecated", False)
        platforms = ",".join(obj.get("x_mitre_platforms", [])) if obj.get("x_mitre_platforms") else None
        mitre_version = obj.get("x_mitre_version", "1.0")
        last_updated = datetime.utcnow()

        # Map tactic
        tactic_id = None
        for phase in obj.get("kill_chain_phases", []):
            phase_name = phase.get("phase_name")
            tactic_id = PHASE_NAME_TO_ID.get(phase_name)
            if tactic_id:
                break

        if not tactic_id:
            skipped_count += 1
            print(f"[WARN] Skipping technique {technique_id} – no tactic found")
            continue

        technique = MitreTechnique(
            technique_id=technique_id,
            name=name,
            description=description,
            url=url,
            deprecated=deprecated,
            platforms=platforms,
            last_updated=last_updated,
            source="local",
            mitre_version=mitre_version,
            tactic_id=tactic_id,
        )

        try:
            db.session.merge(technique)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            skipped_count += 1
            print(f"[ERROR] Failed to insert technique {technique_id}: {e}")

    print("[INFO] MITRE ATT&CK data loaded successfully.")
    print(f"[INFO] Total skipped techniques: {skipped_count}")
