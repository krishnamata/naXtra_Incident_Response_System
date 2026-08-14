import os
import re
import json
from xml.etree import ElementTree as ET

from app.utils.log_type_registry import normalize_log_type

DECODER_DIR = "app/rules/wazuh-ruleset/decoders/"
RULES_DIR = "app/rules/wazuh-ruleset/rules/"
OUTPUT_FILE = "app/utils/decoder_logtype_rule_map.py"

# Agent-type detection from decoder name
AGENT_TYPE_KEYWORDS = {
    "linux": ["linux", "auditd", "syslog", "sulog", "journal"],
    "windows": ["windows", "sysmon", "win"],
    "network_device": ["cisco", "fortigate", "checkpoint", "netscaler", "juniper", "pix", "asa"],
    "cloud": ["aws", "azure"],
    "container": ["docker", "k8s", "podman"],
}

# Explicit overrides for known decoders to prevent misclassification
DECODER_AGENT_OVERRIDE = {
    "windows-ntsyslog": "windows",
    "Windows-defender": "windows",
    "Sysmon-EventID#1": "windows",
    "Sysmon-EventID#11": "windows",
    "Sysmon-EventID#15": "windows",
    # Add more overrides as needed
}



def extract_decoders(decoder_dir):
    decoders = []
    for root, _, files in os.walk(decoder_dir):
        for file in files:
            if file.endswith(".xml"):
                with open(os.path.join(root, file)) as f:
                    content = f.read()
                    matches = re.findall(r'<decoder name="([^"]+)"', content)
                    decoders.extend(matches)
    return sorted(set(decoders))

def detect_agent_type(decoder_name):
    decoder_name_lower = decoder_name.lower()
    # check override first
    if decoder_name in DECODER_AGENT_OVERRIDE:
        return DECODER_AGENT_OVERRIDE[decoder_name]
    for agent, keywords in AGENT_TYPE_KEYWORDS.items():
        if any(k in decoder_name_lower for k in keywords):
            return agent
    return "other"  # fallback

def extract_rule_groups(rules_dir):
    decoder_to_rule_groups = {}
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if not file.endswith(".xml"):
                continue
            try:
                tree = ET.parse(os.path.join(root, file))
            except ET.ParseError as e:
                print(f"Skipping {file} due to parse error: {e}")
                continue
            root_elem = tree.getroot()
            for rule in root_elem.findall(".//rule"):
                decoder_name = rule.get("decoder")
                if not decoder_name:
                    continue
                groups = rule.get("groups")
                if groups:
                    groups_list = [g.strip() for g in groups.split(",") if g.strip()]
                else:
                    groups_list = ["generic"]
                decoder_to_rule_groups.setdefault(decoder_name, set()).update(groups_list)
    # convert sets to sorted lists
    for k, v in decoder_to_rule_groups.items():
        decoder_to_rule_groups[k] = sorted(list(v))
    return decoder_to_rule_groups

def map_decoder_to_logtype_and_rule(decoders, decoder_to_rule_groups):
    mapping = {}
    for decoder in decoders:
        agent_type = detect_agent_type(decoder)
        log_type = normalize_log_type(decoder, agent_type=agent_type)
        rule_groups = decoder_to_rule_groups.get(decoder, ["generic"])
        mapping[decoder] = {"log_type": log_type, "rule_groups": rule_groups}
    return mapping

def save_mapping(mapping, output_file):
    # Ensure 'other' exists
    if "other" not in mapping:
        mapping["other"] = {"log_type": "other", "rule_groups": ["rule_9999"]}

    with open(output_file, "w") as f:
        f.write("# Auto-generated decoder -> log_type -> rule_groups mapping\n")
        f.write("DECODER_LOGTYPE_RULE_MAP = ")
        f.write(json.dumps(mapping, indent=4))
        f.write("\n")


if __name__ == "__main__":
    decoders = extract_decoders(DECODER_DIR)
    decoder_to_rule_groups = extract_rule_groups(RULES_DIR)
    mapping = map_decoder_to_logtype_and_rule(decoders, decoder_to_rule_groups)
    save_mapping(mapping, OUTPUT_FILE)
    print(f"Mapping saved to {OUTPUT_FILE}")
