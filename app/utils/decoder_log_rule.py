# app/utils/decoder_log_rule.py

import os
import xml.etree.ElementTree as ET

# Paths to Wazuh decoders and rules
DECODER_DIR = "app/rules/wazuh-ruleset/decoders"
RULE_DIR = "app/rules/wazuh-ruleset/rules"

# Global mapping: decoder → log_type → list of rules
DECODER_RULE_MAP = {}

def apply_decoders(raw_message, decoders_cache=None):
    """
    Minimal decoder function that just identifies decoder and
    returns the raw message as parsed log for testing.
    """
    decoder_name = identify_decoder(raw_message)
    return {"message": raw_message}, decoder_name




# ------------------------------
# 1. Parse decoders from XML
# ------------------------------
decoder_names = []
for file in os.listdir(DECODER_DIR):
    if file.endswith(".xml"):
        path = os.path.join(DECODER_DIR, file)
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            for decoder in root.findall("decoder"):
                name = decoder.attrib.get("name")
                if name:
                    decoder_names.append(name)
        except Exception as e:
            print(f"[ERROR] Parsing decoder file {file}: {e}")

print(f"[INFO] Total decoders found: {len(decoder_names)}")

# ------------------------------
# 2. Parse rules from XML
# ------------------------------
rules_map = []
for file in os.listdir(RULE_DIR):
    if file.endswith(".xml"):
        path = os.path.join(RULE_DIR, file)
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            for rule in root.findall("rule"):
                rule_id = rule.attrib.get("id")
                rule_title = rule.findtext("description") or rule_id
                decoder_refs = [d.text for d in rule.findall("decoder")]
                log_types = [lt.text for lt in rule.findall("log")]
                rules_map.append({
                    "rule_id": rule_id,
                    "rule_title": rule_title,
                    "decoders": decoder_refs,
                    "log_types": log_types
                })
        except Exception as e:
            print(f"[ERROR] Parsing rule file {file}: {e}")

print(f"[INFO] Total rules processed: {len(rules_map)}")

# ------------------------------
# 3. Build DECODER_RULE_MAP
# ------------------------------
for r in rules_map:
    for decoder in r["decoders"]:
        if decoder not in DECODER_RULE_MAP:
            DECODER_RULE_MAP[decoder] = {}
        for log_type in r["log_types"]:
            if log_type not in DECODER_RULE_MAP[decoder]:
                DECODER_RULE_MAP[decoder][log_type] = []
            DECODER_RULE_MAP[decoder][log_type].append({
                "id": r["rule_id"],
                "title": r["rule_title"],
                "enabled": True,
                "detection": {"conditions": [{"always": True}]},  # always-match for testing
            })

# ------------------------------
# 4. Add generic fallback rules
# ------------------------------
# Linux generic
DECODER_RULE_MAP.setdefault("linux_generic", {})
DECODER_RULE_MAP["linux_generic"]["other_linux"] = [
    {
        "id": "GEN-LINUX-001",
        "title": "Generic Linux rule",
        "enabled": True,
        "description": "Always-match fallback rule for Linux",
        "detection": {"conditions": [{"always": True}]},
    }
]

# Windows generic
DECODER_RULE_MAP.setdefault("windows_generic", {})
DECODER_RULE_MAP["windows_generic"]["other_windows"] = [
    {
        "id": "GEN-WIN-001",
        "title": "Generic Windows rule",
        "enabled": True,
        "description": "Always-match fallback rule for Windows",
        "detection": {"conditions": [{"always": True}]},
    }
]

# ------------------------------
# 5. Identify decoder from raw log
# ------------------------------
def identify_decoder(raw_log: str) -> str:
    raw_log_lower = (raw_log or "").lower()
    if "sshd" in raw_log_lower or "failed password" in raw_log_lower:
        return "sshd"
    if "windows" in raw_log_lower or "winlogon" in raw_log_lower:
        return "windows"
    if "firewall" in raw_log_lower or "iptables" in raw_log_lower:
        return "firewall"
    if "http" in raw_log_lower or "apache" in raw_log_lower:
        return "web"
    if "linux" in raw_log_lower:
        return "sshd"
    return "generic"

# ------------------------------
# 6. Get decoder and rules for a log
# ------------------------------
def get_decoder_and_rules(log_type: str, raw_log: str, agent_type="linux"):
    from app.utils.log_type_registry import normalize_log_type

    # Normalize log type
    log_type = normalize_log_type(log_type, agent_type=agent_type)

    # Identify decoder from raw log
    decoder_name = identify_decoder(raw_log)

    # Try to get rules
    rules = DECODER_RULE_MAP.get(decoder_name, {}).get(log_type, [])

    # Fallback to generic always-match rules
    if not rules:
        if agent_type == "windows":
            decoder_name = "windows_generic"
            log_type_fallback = "other_windows"
        else:
            decoder_name = "linux_generic"
            log_type_fallback = "other_linux"

        rules = DECODER_RULE_MAP.get(decoder_name, {}).get(log_type_fallback, [])

    return decoder_name, rules



# ------------------------------
# 7. Utility to get full map
# ------------------------------
def build_decoder_rule_map():
    return DECODER_RULE_MAP
