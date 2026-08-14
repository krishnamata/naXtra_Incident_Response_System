import os
import xml.etree.ElementTree as ET

RULES_DIR = "app/rules/wazuh-ruleset/rules"
OUTPUT_FILE = "app/utils/generated_logtype_ruleset_map.py"

# Map known Wazuh rule groups to your log types
GROUP_TO_LOGTYPE = {
    "system_error": "journal",
    "systemd": "journal",
    "auditd": "journal",
    "pam": "authlog",
    "sshd": "authlog",
    "firewalld": "syslog",
    "mysql": "mysql",
    "mariadb": "mysql",
    "apache": "apache",
    "nginx": "nginx",
    "postfix": "mail",
    "dovecot": "mail",
    "sendmail": "mail",
    # Add more as needed
}

def generate_mapping():
    mapping = {}
    for fname in os.listdir(RULES_DIR):
        if not fname.endswith("_rules.xml"):
            continue
        filepath = os.path.join(RULES_DIR, fname)
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            for group_elem in root.findall(".//group"):
                groups = group_elem.text or ""
                for g in groups.split(","):
                    g = g.strip()
                    if g in GROUP_TO_LOGTYPE:
                        lt = GROUP_TO_LOGTYPE[g]
                        mapping.setdefault(lt, []).append(fname)
        except ET.ParseError:
            print(f"[WARN] Failed to parse XML: {fname}")
    # Deduplicate and sort
    for lt in mapping:
        mapping[lt] = sorted(set(mapping[lt]))
    return mapping

def save_mapping(mapping, outfile=OUTPUT_FILE):
    with open(outfile, "w") as f:
        f.write("# Auto-generated logtype → ruleset mapping\n")
        f.write("LOGTYPE_TO_RULESETS = {\n")
        for lt, files in mapping.items():
            f.write(f'    "{lt}": {files},\n')
        f.write("}\n")
    print(f"[INFO] Mapping saved to {outfile}")

if __name__ == "__main__":
    mapping = generate_mapping()
    save_mapping(mapping)
    print("[DEBUG] Generated mapping:")
    for lt, files in mapping.items():
        print(f"  {lt}: {files}")
