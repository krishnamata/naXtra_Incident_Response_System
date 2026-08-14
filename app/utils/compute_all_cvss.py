# app/utils/generate_full_cvss_json.py
import os
import xml.etree.ElementTree as ET
import json
from app.utils.cvss_loader import compute_cvss_score

RULE_DIR = "app/rules/wazuh-ruleset/rules/"
OUTPUT_JSON = "app/utils/cvss_rule_mapping_full.json"

# Default mapping based on Wazuh rule level
LEVEL_TO_CVSS = {
    0: {"AV":"N","AC":"H","PR":"N","UI":"N","C":"N","I":"N","A":"N","S":"U"},
    3: {"AV":"L","AC":"L","PR":"L","UI":"N","C":"L","I":"L","A":"L","S":"U"},
    5: {"AV":"L","AC":"L","PR":"L","UI":"N","C":"M","I":"M","A":"M","S":"U"},
    8: {"AV":"L","AC":"L","PR":"L","UI":"N","C":"H","I":"H","A":"H","S":"U"},
    10: {"AV":"N","AC":"L","PR":"N","UI":"R","C":"H","I":"H","A":"H","S":"U"}
}

def extract_rule_data(xml_file):
    rules_data = {}
    tree = ET.parse(xml_file)
    root = tree.getroot()
    for rule in root.findall(".//rule"):
        rule_id = rule.get("id")
        level = int(rule.get("level", 0))
        description = rule.findtext("description", default="No description")
        mitre_elem = rule.find("mitre")
        mitre_id = mitre_elem.findtext("id") if mitre_elem is not None else None

        metrics = LEVEL_TO_CVSS.get(level, LEVEL_TO_CVSS[3])
        try:
            score = compute_cvss_score(metrics)
        except Exception:
            score = 0.0

        rules_data[rule_id] = {
            "rule_name": description,
            "mitre_attack": mitre_id,
            "metrics": metrics,
            "cvss_score": score
        }
    return rules_data

def main():
    all_rules = {}
    for filename in os.listdir(RULE_DIR):
        if filename.endswith(".xml"):
            xml_path = os.path.join(RULE_DIR, filename)
            rules_data = extract_rule_data(xml_path)
            all_rules.update(rules_data)
            print(f"[INFO] Processed {filename}: {len(rules_data)} rules found.")
    
    with open(OUTPUT_JSON, "w") as f:
        json.dump(all_rules, f, indent=2)
    
    print(f"[INFO] Full CVSS JSON mapping saved to {OUTPUT_JSON}. Total rules: {len(all_rules)}")

if __name__ == "__main__":
    main()
