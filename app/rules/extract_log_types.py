import os
import xml.etree.ElementTree as ET

RULES_DIR = "app/rules/wazuh-ruleset/rules/"

def extract_log_types(rules_dir):
    log_types = set()
    for filename in os.listdir(rules_dir):
        if filename.endswith(".xml"):
            filepath = os.path.join(rules_dir, filename)
            try:
                tree = ET.parse(filepath)
                root = tree.getroot()
                for group in root.findall("group"):
                    # Group name attribute or text content
                    name_attr = group.attrib.get("name")
                    if name_attr:
                        for name in name_attr.split(","):
                            log_types.add(name.strip())
                    elif group.text:
                        for name in group.text.split(","):
                            log_types.add(name.strip())
            except Exception as e:
                print(f"Error parsing {filename}: {e}")
    return sorted(log_types)

if __name__ == "__main__":
    log_types = extract_log_types(RULES_DIR)
    print("Extracted log_types:")
    for lt in log_types:
        print(lt)
