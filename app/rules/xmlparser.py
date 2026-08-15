import os
import json
import xml.etree.ElementTree as ET

def extract_sample_logs_from_rules(rules_dir):
    sample_logs = {}

    for filename in os.listdir(rules_dir):
        if not filename.endswith(".xml"):
            continue

        filepath = os.path.join(rules_dir, filename)
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            # Find decoded_as value for log_type (first occurrence in file)
            log_type_elem = root.find(".//decoded_as")
            log_type = log_type_elem.text.strip() if log_type_elem is not None else None

            if not log_type:
                # If no decoded_as, try to get group name as fallback
                group_elem = root.find(".//group")
                log_type = group_elem.attrib.get("name", "").split(",")[0] if group_elem is not None else None

            if not log_type:
                # Skip files with no log_type
                continue

            # Initialize log sample for this log_type if not exists
            if log_type not in sample_logs:
                sample_logs[log_type] = {"log_type": log_type}

            # Extract field names and sample values from <field> and <match> tags
            # We'll just pick one sample value per field per file
            for rule in root.findall(".//rule"):
                # Extract fields
                for field_elem in rule.findall("field"):
                    field_name = field_elem.attrib.get("name")
                    field_value = field_elem.text.strip() if field_elem.text else "sample_value"
                    if field_name and field_name not in sample_logs[log_type]:
                        sample_logs[log_type][field_name] = field_value

                # Extract match tag as possible message or indicator field
                match_elem = rule.find("match")
                if match_elem is not None:
                    match_text = match_elem.text.strip()
                    # Add 'message' or similar field if not present
                    if "message" not in sample_logs[log_type]:
                        sample_logs[log_type]["message"] = match_text

                # Optionally extract description for info
                description_elem = rule.find("description")
                if description_elem is not None and "description" not in sample_logs[log_type]:
                    sample_logs[log_type]["description"] = description_elem.text.strip()

        except ET.ParseError:
            print(f"Warning: Failed to parse XML file {filepath}")

    return sample_logs


if __name__ == "__main__":
    RULES_DIR = "app/rules/wazuh-ruleset/rules"  # Change as needed
    samples = extract_sample_logs_from_rules(RULES_DIR)

    with open("sample_logs.json", "w") as f:
        json.dump(samples, f, indent=4)

    print("Sample logs JSON generated in sample_logs.json")
