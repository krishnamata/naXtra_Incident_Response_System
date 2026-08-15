import os
import sys
import git
import yaml
from datetime import datetime


# Dynamically insert project root (/var/www/modular-soar) into sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, '../../'))
sys.path.insert(0, PROJECT_ROOT)


# Add your app directory to sys.path for imports
sys.path.append('/var/www/modular-soar')

from app.main import app, db
from app.models.detection_rule import DetectionRule

# === Configuration ===
REPO_URL = "https://github.com/Krishnasec/naXtraSOAR.git"
CLONE_DIR = "/var/www/modular-soar/github_sync"
RULE_EXTENSIONS = ('.yaml', '.yml')

def pull_or_clone_repo():
    if not os.path.exists(CLONE_DIR):
        print("[INFO] Cloning repository...")
        git.Repo.clone_from(REPO_URL, CLONE_DIR)
    else:
        print("[INFO] Pulling latest updates...")
        repo = git.Repo(CLONE_DIR)
        repo.remote().pull()

def load_yaml_rules():
    print("[INFO] Loading YAML rules...")
    rules = []
    for file in os.listdir(CLONE_DIR):
        if file.endswith(RULE_EXTENSIONS):
            file_path = os.path.join(CLONE_DIR, file)
            try:
                with open(file_path, 'r') as f:
                    rule = yaml.safe_load(f)
                    if rule:
                        rule['__filename__'] = file
                        rules.append(rule)
                        print(f"[✓] Loaded: {file} -> {rule.get('title', 'No Title')}")
            except Exception as e:
                print(f"[✗] Failed to load {file}: {e}")
    return rules


def save_rules_to_db(rules):
    with app.app_context():
        for rule in rules:
            existing = DetectionRule.query.filter_by(filename=rule['__filename__']).first()
            if existing:
                # Update existing rule
                existing.rule_id = rule.get('id')
                existing.title = rule.get('title', 'Untitled')
                existing.tactic = rule.get('tactic')
                existing.description = rule.get('description')
                existing.updated_at = datetime.utcnow()
                print(f"[↑] Updated rule: {existing.title}")
            else:
                # Add new rule
                new_rule = DetectionRule(
                    rule_id=rule.get('id'),
                    title=rule.get('title', 'Untitled'),
                    tactic=rule.get('tactic'),
                    description=rule.get('description'),
                    filename=rule['__filename__'],
                    source="github",
                    updated_at=datetime.utcnow()
                )
                db.session.add(new_rule)
                print(f"[+] Added new rule: {new_rule.title}")
        db.session.commit()
        print("[✓] All rules saved to database.")




if __name__ == "__main__":
    print(f"[{datetime.now()}] Starting GitHub Rule Sync...")
    pull_or_clone_repo()
    rules = load_yaml_rules()
    print(f"[✓] Total rules loaded: {len(rules)}")
