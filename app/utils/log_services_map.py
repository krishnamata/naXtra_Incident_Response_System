import os

RULES_DIR = "app/rules/wazuh-ruleset/rules"
OUTPUT_FILE = "app/utils/generated_logtype_ruleset_map.py"

# Predefined mapping candidates (service keywords → log_types they relate to)
SERVICE_KEYWORDS = {
    "pam": ["authlog"],
    "sshd": ["authlog"],
    "systemd": ["authlog", "syslog", "kernlog"],
    "auditd": ["authlog", "syslog", "kernlog"],
    "firewalld": ["syslog", "kernlog"],
    "apache": ["apache"],
    "nginx": ["nginx"],
    "mysql": ["syslog", "mysql"],
    "mariadb": ["syslog", "mysql"],
    "postgresql": ["postgresql"],
    "dovecot": ["mail"],
    "postfix": ["mail"],
    "sendmail": ["mail"],
    "journal": ["journal"],
    # extend with others as needed
}

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

        # --- 1. Map based on filename keywords ---
        service_name = fname.replace("_rules.xml", "")
        for keyword, logtypes in SERVICE_KEYWORDS.items():
            if keyword in service_name:
                for lt in logtypes:
                    mapping.setdefault(lt, []).append(fname)

        # --- 2. Map based on XML <group> tags ---
        try:
            import xml.etree.ElementTree as ET
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
