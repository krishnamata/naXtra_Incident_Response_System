from app.rules.rules_loader import RULES_CACHE
from app.rules.rules_engine import RuleEngine
from app.utils.log_type_registry import normalize_log_type

# Initialize engine
engine = RuleEngine(RULES_CACHE)

# Pick a log type
log_type = 'other_linux'

# List all rules whose group/log_types include this log_type
applicable_rules = [
    r for r in RULES_CACHE
    if log_type in [normalize_log_type(t) for t in r.get('log_types', [])]
]

print(f"Total rules applicable to '{log_type}': {len(applicable_rules)}")
for r in applicable_rules[:5]:  # preview first 5
    print(r['id'], r['title'], r['log_types'])

# Test each log against these rules
from app.dlp import fetch_logs_by_type

logs = fetch_logs_by_type(log_type, limit=3)

for log in logs:
    matched_rules = engine.match_log(log)
    if matched_rules:
        print(f"\nLog ID {log['id']} matched rules:")
        for mr in matched_rules:
            print(f"  - {mr['rule_id']} | {mr['title']}")
    else:
        print(f"\nLog ID {log['id']} matched 0 rules")
