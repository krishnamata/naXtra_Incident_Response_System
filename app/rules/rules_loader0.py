import os
import xml.etree.ElementTree as ET
from app.rules.rules_engine import RuleEngine
from app.utils.mitre_map import MITRE_KEYWORD_MAP
#from app import create_app, db
#from app.models import RuleIndex


def parse_detection_conditions(rule):
    conditions = []

    if not isinstance(rule, ET.Element):
        #print(f"[ERROR] Unexpected rule type: {type(rule)} — expected xml.etree.ElementTree.Element")
        return conditions

    for child in rule:
        if not isinstance(child.tag, str):
            #print(f"[ERROR] Invalid child tag in rule ID: {rule.attrib.get('id')}")
            continue

        # Extended detection tags parsing
        if child.tag in {'field', 'match', 'same_field', 'same_source_ip', 'if_sid',
                         'regex', 'frequency', 'timeframe', 'if_group', 'if_matched_group',
                         'same_location'}:

            condition = {'type': child.tag}

            if child.tag == 'field':
                condition['name'] = child.attrib.get('name')
                condition['operation'] = child.attrib.get('operation')
                condition['value'] = child.text.strip() if child.text else ''

            elif child.tag == 'match':
                condition['value'] = child.text.strip() if child.text else ''

            elif child.tag == 'regex':
                condition['value'] = child.text.strip() if child.text else ''

            elif child.tag == 'frequency':
                # frequency usually integer
                try:
                    condition['value'] = int(child.text.strip()) if child.text else 0
                except ValueError:
                    condition['value'] = 0

            elif child.tag == 'timeframe':
                # timeframe usually integer seconds
                try:
                    condition['value'] = int(child.text.strip()) if child.text else 0
                except ValueError:
                    condition['value'] = 0

            elif child.tag == 'same_field':
                condition['name'] = child.attrib.get('name')

            elif child.tag == 'same_source_ip':
                # no attributes, just presence means condition applies
                pass

            elif child.tag == 'same_location':
                # no attributes, just presence means condition applies
                pass

            elif child.tag == 'if_sid':
                condition['sid'] = child.text.strip() if child.text else ''

            elif child.tag == 'if_group':
                condition['group'] = child.text.strip() if child.text else ''

            elif child.tag == 'if_matched_group':
                condition['group'] = child.text.strip() if child.text else ''

            conditions.append(condition)

    return conditions


def parse_rule_description(rule_elem, severity):
    """
    Extract a descriptive text, MITRE ID, and rule ID from the XML rule element.
    Priority for description:
    1) <description> tag
    2) <match> tag
    3) MITRE ID tag
    4) <if_sid> tag
    5) fallback to rule ID if severity >= 9
    Returns a tuple (description_text, mitre_id, rule_id)
    or (None, None, None) if no description is found.
    """

    description_text = None
    mitre_id = None
    rule_id = rule_elem.attrib.get('id')

    # Try <description>
    desc = rule_elem.findtext('description')
    if desc and desc.strip():
        description_text = desc.strip()

    # If no description, try first <match> tag text
    if not description_text:
        matches = [m.text.strip() for m in rule_elem.findall('match') if m.text and m.text.strip()]
        if matches:
            description_text = matches[0]

    # Extract MITRE ID if present
    mitre_elem = rule_elem.find('mitre')
    if mitre_elem is not None:
        mitre_id_elem = mitre_elem.find('id')
        if mitre_id_elem is not None and mitre_id_elem.text and mitre_id_elem.text.strip():
            mitre_id = mitre_id_elem.text.strip()

    # If still no description, try <if_sid>
    if not description_text:
        if_sids = [sid.text.strip() for sid in rule_elem.findall('if_sid') if sid.text and sid.text.strip()]
        if if_sids:
            description_text = f"Related Rule SID: {if_sids[0]}"

    # Fallback description based on rule ID if severity high
    if not description_text and severity >= 9 and rule_id:
        description_text = f"Rule ID: {rule_id}"

    # If nothing found, discard this rule (return None)
    if not description_text:
        return None, None, None

    return description_text, mitre_id, rule_id


def load_rules(rules_dir='rules'):
    """
    Loads all XML rule files from the given directory,
    parses each rule to extract metadata, detection conditions,
    and performs automatic MITRE ID mapping when missing.

    Returns a list of rule dictionaries ready for detection.
    """

    rules = []

    for filename in os.listdir(rules_dir):
        if filename.endswith('.xml'):
            filepath = os.path.join(rules_dir, filename)
            #print(f"[*] Parsing XML file: {filepath}")
            try:
                tree = ET.parse(filepath)
                root = tree.getroot()

                # Either root is <ruleset> or <group>; normalize to get all <group> elements
                if root.tag == 'group':
                    groups = [root]
                else:
                    groups = root.findall('.//group')

                #print(f"Found {len(groups)} group(s) in {filename}")

                for group in groups:
                    group_name = group.attrib.get('name', '')
                    group_names = [g.strip() for g in group_name.split(',') if g.strip()]

                    for rule in group.findall('rule'):
                        # Use improved description parsing
                        severity = 0
                        try:
                            severity = int(rule.attrib.get('level', '0'))
                        except ValueError:
                            print(f"[WARNING] Invalid severity level in rule id {rule.attrib.get('id')}")

                        description_text, mitre_id, rule_id = parse_rule_description(rule, severity)

                        if not description_text:
                            # Skip rules without a description fallback
                            continue

                        keywords = [m.text.strip() for m in rule.findall('match') if m.text and m.text.strip()]
                        if not keywords:
                            keywords = [r.text.strip() for r in rule.findall('regex') if r.text and r.text.strip()]

                        # Extract MITRE info, override if present
                        mitre_elem = rule.find('mitre')
                        if mitre_elem is not None:
                            mitre_id_elem = mitre_elem.find('id')
                            if mitre_id_elem is not None and mitre_id_elem.text and mitre_id_elem.text.strip():
                                mitre_id = mitre_id_elem.text.strip()
                            else:
                                mitre_id = 'NA'
                        else:
                            mitre_id = mitre_id or 'NA'

                        technique_link = (f"https://attack.mitre.org/techniques/{mitre_id}/"
                                          if mitre_id != 'NA' else 'NA')

                        # Auto-map MITRE ID if missing
                        if mitre_id == 'NA':
                            text_to_search = ' '.join(keywords).lower() + ' ' + (description_text.lower() if description_text else '')
                            for keyword, mitre_info in MITRE_KEYWORD_MAP.items():
                                if keyword.lower() in text_to_search:
                                    if isinstance(mitre_info, str):
                                        mitre_id = mitre_info
                                    elif isinstance(mitre_info, dict):
                                        mitre_id = mitre_info.get('id', 'NA')
                                    else:
                                        mitre_id = 'NA'
                                    technique_link = f"https://attack.mitre.org/techniques/{mitre_id}/" if mitre_id != 'NA' else 'NA'
                                    #print(f"[MITRE AUTO-MAP] Rule ID {rule_id} matched keyword '{keyword}' with MITRE {mitre_id}")
                                    break

                        # Parse frequency and timeframe for alert correlation (if present)
                        frequency = None
                        timeframe = None
                        freq_elem = rule.find('frequency')
                        if freq_elem is not None and freq_elem.text and freq_elem.text.strip().isdigit():
                            frequency = int(freq_elem.text.strip())
                        timeframe_elem = rule.find('timeframe')
                        if timeframe_elem is not None and timeframe_elem.text and timeframe_elem.text.strip().isdigit():
                            timeframe = int(timeframe_elem.text.strip())

                        rule_dict = {
                            'id': rule_id,
                            'filename': filename,
                            'group': group_name,
                            'log_types': group_names,
                            'title': description_text,
                            'description': description_text,
                            'severity': severity,
                            'keywords': keywords,
                            'technique_id': mitre_id,
                            'technique_link': technique_link,
                            'frequency': frequency,
                            'timeframe': timeframe,
                            'detection': {
                                'conditions': parse_detection_conditions(rule)
                            },
                            'element': rule
                        }

                        rules.append(rule_dict)

            except Exception as e:
                print(f"[ERROR] Failed to process file: {filename}\nException: {e}")

    print(f"Total rules loaded: {len(rules)}")
    return rules


# Example usage for testing
if __name__ == '__main__':
    # Import here to avoid circular import issues
    from app import create_app
    from app.extensions import db
    from app.models import RuleIndex

    app = create_app()
    with app.app_context():
        # Optional: clear old entries before inserting new
        db.session.query(RuleIndex).delete()
        rules = load_rules("app/rules/wazuh-ruleset/rules/")
        inserted = 0

        for r in rules:
            rule_index = RuleIndex(
                rule_id=r['id'],
                title=r['title'],
                description=r['description'],
                severity=r['severity'],
                keywords=", ".join(r['keywords']),
                log_type=", ".join(r['log_types']),
                mitre_id=r['technique_id'],
                mitre_link=r['technique_link'],
                file_path=r['filename'],
                type='rule '
            )

            db.session.add(rule_index)
            inserted += 1

        db.session.commit()
        print(f"✅ Inserted {inserted} rules into RuleIndex table.")
