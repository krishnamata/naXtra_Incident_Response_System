import os
import xml.etree.ElementTree as ET
from app.rules.rules_engine import RuleEngine
from app.utils.mitre_map import MITRE_KEYWORD_MAP
from app.utils.log_type_registry import normalize_log_type
from app.utils.log_services_map import generate_mapping

# Rules directory
RULES_DIR = 'app/rules/wazuh-ruleset/rules'

# Log_type → ruleset mapping
LOGTYPE_TO_RULESETS = generate_mapping()


def parse_detection_conditions(rule_elem):
    """Parse detection conditions from an XML rule element."""
    conditions = []
    for child in rule_elem:
        if not isinstance(child.tag, str) or child.tag not in {
            'field', 'match', 'same_field', 'same_source_ip', 'if_sid',
            'regex', 'frequency', 'timeframe', 'if_group', 'if_matched_group', 'same_location'
        }:
            continue

        cond = {'type': child.tag}
        if child.tag == 'field':
            cond.update({
                'name': child.attrib.get('name'),
                'operation': child.attrib.get('operation'),
                'value': (child.text or '').strip()
            })
        elif child.tag in {'match', 'regex'}:
            cond['value'] = (child.text or '').strip()
        elif child.tag in {'frequency', 'timeframe'}:
            try:
                cond['value'] = int((child.text or '0').strip())
            except ValueError:
                cond['value'] = 0
        elif child.tag == 'same_field':
            cond['name'] = child.attrib.get('name')
        elif child.tag == 'if_sid':
            cond['sid'] = (child.text or '').strip()
        elif child.tag in {'if_group', 'if_matched_group'}:
            cond['group'] = (child.text or '').strip()

        conditions.append(cond)

    return conditions


def parse_rule_description(rule_elem, severity):
    """Get rule description and MITRE info."""
    rule_id = rule_elem.attrib.get('id')
    desc = (rule_elem.findtext('description') or '').strip()
    mitre_elem = rule_elem.find('mitre')
    mitre_id = None

    if not desc:
        matches = [m.text.strip() for m in rule_elem.findall('match') if m.text and m.text.strip()]
        desc = matches[0] if matches else None

    if mitre_elem is not None:
        mitre_id_elem = mitre_elem.find('id')
        if mitre_id_elem is not None and mitre_id_elem.text:
            mitre_id = mitre_id_elem.text.strip()

    if not desc:
        sids = [sid.text.strip() for sid in rule_elem.findall('if_sid') if sid.text and sid.text.strip()]
        if sids:
            desc = f"Related Rule SID: {sids[0]}"

    if not desc and severity >= 9 and rule_id:
        desc = f"Rule ID: {rule_id}"

    if not desc:
        return None, None, None

    return desc, mitre_id, rule_id


def parse_rules_from_root(root, filename):
    """Extract all rules from an XML root."""
    rules = []
    groups = [root] if root.tag == 'group' else root.findall('.//group')

    for group in groups:
        group_name = group.attrib.get('name', '')
        log_types = [normalize_log_type(g.strip().lower()) for g in group_name.split(',') if g.strip()] or ['generic']

        for rule in group.findall('rule'):
            severity = int(rule.attrib.get('level', '0') or 0)
            description, mitre_id, rule_id = parse_rule_description(rule, severity)
            if not description:
                continue

            keywords = [m.text.strip() for m in rule.findall('match') if m.text and m.text.strip()] \
                       or [r.text.strip() for r in rule.findall('regex') if r.text and r.text.strip()]

            if not mitre_id:
                text_to_search = ' '.join(keywords).lower() + ' ' + description.lower()
                for k, v in MITRE_KEYWORD_MAP.items():
                    if k.lower() in text_to_search:
                        mitre_id = v if isinstance(v, str) else v.get('id', 'NA')
                        break

            technique_link = f"https://attack.mitre.org/techniques/{mitre_id}/" if mitre_id else 'NA'

            freq_elem = rule.find('frequency')
            timeframe_elem = rule.find('timeframe')
            frequency = int(freq_elem.text.strip()) if freq_elem is not None and freq_elem.text and freq_elem.text.strip().isdigit() else None
            timeframe = int(timeframe_elem.text.strip()) if timeframe_elem is not None and timeframe_elem.text and timeframe_elem.text.strip().isdigit() else None

            rules.append({
                'id': rule_id,
                'filename': filename,
                'group': group_name,
                'log_types': log_types,
                'title': description,
                'description': description,
                'severity': severity,
                'keywords': keywords,
                'technique_id': mitre_id or 'NA',
                'technique_link': technique_link,
                'frequency': frequency,
                'timeframe': timeframe,
                'detection': {'conditions': parse_detection_conditions(rule)},
                'element': rule
            })

    return rules


def load_rules(path):
    """Load all rules from directory or single XML file."""
    files = []
    if os.path.isdir(path):
        files = [os.path.join(path, f) for f in os.listdir(path) if f.endswith('.xml')]
    elif os.path.isfile(path):
        files = [path]
    else:
        raise FileNotFoundError(f"Rules path not found: {path}")

    all_rules = []
    for f in files:
        try:
            tree = ET.parse(f)
            root = tree.getroot()
            all_rules.extend(parse_rules_from_root(root, os.path.basename(f)))
        except Exception as e:
            print(f"[ERROR] Failed to parse {f}: {e}")

    return all_rules


def build_rules_lookup(rules):
    """Build rules lookup by ID and keywords."""
    by_id, keyword_map = {}, {}
    for rule in rules:
        rid = rule.get('id')
        if rid:
            by_id[rid] = rule
        for kw in rule.get('keywords', []):
            keyword_map.setdefault(kw.lower(), []).append(rule)
    return by_id, keyword_map


def load_rules_for_logtype(log_type, rules_dir=RULES_DIR):
    """Load only rules relevant to a given log_type."""
    xml_files = LOGTYPE_TO_RULESETS.get(log_type, [])
    rules = []
    for fname in xml_files:
        path = os.path.join(rules_dir, fname)
        if os.path.isfile(path):
            rules.extend(load_rules(path))
    return rules


# Preload all rules
RULES_CACHE = load_rules(RULES_DIR)
RULES_BY_ID, RULES_KEYWORD_MAP = build_rules_lookup(RULES_CACHE)
print(f"[INFO] Total rules loaded: {len(RULES_CACHE)}")
