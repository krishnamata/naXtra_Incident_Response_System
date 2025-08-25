from app.extensions import db
import click
import os
import xml.etree.ElementTree as ET



RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')



@click.command("import_rules")
def import_rules_command():
    """Import XML rule definitions into RuleIndex table."""
    imported = 0
    skipped = 0

    for root_dir, _, files in os.walk(RULES_DIR):
        for file_name in files:
            if not file_name.endswith(".xml"):
                continue

            file_path = os.path.join(root_dir, file_name)

            try:
                tree = ET.parse(file_path)
                root = tree.getroot()

                for rule_elem in root.findall(".//rule"):
                    rule_id = rule_elem.get("id")
                    if not rule_id:
                        print(f"[SKIP] Rule without ID in file {file_name}")
                        skipped += 1
                        continue

                    # Check if rule already exists
                    existing_rule = RuleIndex.query.filter_by(rule_id=rule_id).first()
                    if existing_rule:
                        print(f"[SKIP] Rule ID {rule_id} already in DB")
                        skipped += 1
                        continue

                    title = rule_elem.findtext("description") or "N/A"
                    group = rule_elem.findtext("group") or ""
                    type_guess = "winlogbeat" if "win" in file_name.lower() else "linux"

                    new_rule = RuleIndex(
                        rule_id=rule_id,
                        title=title.strip(),
                        keywords=group.strip(),
                        file_path=file_path,
                        type=type_guess
                    )
                    db.session.add(new_rule)
                    imported += 1
                    print(f"[IMPORT] Rule ID {rule_id} imported from file {file_name}")

            except ET.ParseError:
                print(f"[ERROR] Failed to parse XML file: {file_path}")
                skipped += 1
            except Exception as e:
                print(f"[ERROR] Unexpected error on file {file_path}: {e}")
                skipped += 1

    db.session.commit()
    print(f"[INFO] Rule import completed. Imported: {imported}, Skipped: {skipped}")
