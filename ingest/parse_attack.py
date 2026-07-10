"""
Parse the MITRE ATT&CK Enterprise STIX bundle into a flat list of
technique/sub-technique records suitable for embedding into a vector store.

Run standalone to regenerate data/techniques.json:
    python ingest/parse_attack.py
"""
import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
STIX_BUNDLE = DATA_DIR / "enterprise-attack.json"
OUTPUT = DATA_DIR / "techniques.json"


def strip_markdown(text: str) -> str:
    """Remove citation markers and markdown links from ATT&CK descriptions."""
    if not text:
        return ""
    text = re.sub(r"\(Citation:.*?\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text.strip()


def get_external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def parse(bundle_path: Path = STIX_BUNDLE) -> list[dict]:
    bundle = json.loads(bundle_path.read_text())
    objects = bundle["objects"]

    # Build tactic short-name -> display-name lookup from x-mitre-tactic objects
    tactics_by_shortname = {}
    for obj in objects:
        if obj["type"] == "x-mitre-tactic":
            tactics_by_shortname[obj["x_mitre_shortname"]] = obj["name"]

    techniques = []
    for obj in objects:
        if obj["type"] != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = get_external_id(obj)
        if not technique_id:
            continue

        tactic_names = [
            tactics_by_shortname.get(phase["phase_name"], phase["phase_name"])
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
        platforms = obj.get("x_mitre_platforms", [])
        data_sources = obj.get("x_mitre_data_sources", [])
        description = strip_markdown(obj.get("description", ""))

        record = {
            "technique_id": technique_id,
            "name": obj["name"],
            "is_subtechnique": is_subtechnique,
            "parent_technique_id": technique_id.split(".")[0] if is_subtechnique else None,
            "tactics": tactic_names,
            "platforms": platforms,
            "data_sources": data_sources,
            "description": description,
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        }
        techniques.append(record)

    techniques.sort(key=lambda t: t["technique_id"])
    return techniques


if __name__ == "__main__":
    techniques = parse()
    OUTPUT.write_text(json.dumps(techniques, indent=2))
    print(f"Parsed {len(techniques)} techniques/sub-techniques -> {OUTPUT}")
    print("Example record:")
    print(json.dumps(techniques[0], indent=2))
