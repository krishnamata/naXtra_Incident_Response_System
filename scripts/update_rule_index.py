import os
import xml.etree.ElementTree as ET
from app import create_app, db
from app.models import RuleIndex

RULES_DIR = 'app/rules/wazuh-ruleset/rules/'
DECODERS_DIR = os.path.expanduser('~/wazuh-ruleset/decoders/')

def extract_rule_data(filepath, type_):
    entries = []
    tree = ET.parse(filepath)
    root = tree.getroot()

    for rule in root.findall('rule'):
        rule_id = rule.attrib.get('id', 'NA')
        title = rule.findtext('description', '')
        keywords = []

        for tag in ['match', 'field']:
            for kw in rule.findall(tag):
                if kw.text:
                    keywords.append(kw.text.strip())

        entry = RuleIndex(
            rule_id=rule_id,
            title=title[:200],
            keywords=",".join(keywords),
            file_path=filepath,
            type=type_
        )
        entries.append(entry)
    return entries

def scan_and_update():
    app = create_app()
    with app.app_context():
        db.session.query(RuleIndex).delete()

        # Rules
        for filename in os.listdir(RULES_DIR):
            if filename.endswith('.xml'):
                fullpath = os.path.join(RULES_DIR, filename)
                entries = extract_rule_data(fullpath, 'rule')
                db.session.add_all(entries)

        # Decoders
        for filename in os.listdir(DECODERS_DIR):
            if filename.endswith('.xml'):
                fullpath = os.path.join(DECODERS_DIR, filename)
                entries = extract_rule_data(fullpath, 'decoder')
                db.session.add_all(entries)

        db.session.commit()
        print("RuleIndex updated.")

if __name__ == "__main__":
    scan_and_update()
