import re
from app.models.alert import Alert
from app.utils.description_generator import generate_alert_description
from typing import List, Dict, Any
from app.rules.xmlparser import extract_sample_logs_from_rules
import os


class RuleEngine:
    def __init__(self, rules: List[Dict[str,Any]]):
        
        self.rules = rules
        #self.load_rules()

    def match_log(self, log: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Match a single log entry against all loaded rules.
        Returns a list of matched rule metadata.
        """
        matched_rules = []
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            
            log_type = rule.get("log_type")
            if log.get("log_type") != log_type:
                #print(f"[DEBUG] Log type mismatch: log={log.get('log_type')} vs rule={log_type}")
                continue

            matched_keywords = self._match_and_extract_conditions(rule["detection"]["conditions"], log)
            if matched_keywords:
                description = generate_alert_description(
                    severity=rule.get("severity"),
                    technique_id=rule.get("technique_id", NA),
                    matched_keywords=matched_keywords
                )

                matched_rules.append({
                    "rule_id": rule.get("id", "NA"),
                    "title": rule.get("title", "No title"),
                    "severity": rule.get("severity", 0),
                    "description": description, 
                    "technique_id": rule.get("technique_id", "NA"),
                    "technique_link": rule.get("technique_link", "NA"),
                    "matched_keywords": matched_keywords
                })
            

        return matched_rules

    def _match_conditions(self, conditions: List[Dict[str, str]], log: Dict[str, str]) -> bool:
        for condition in conditions:
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")

            log_value = log.get(field, "")
            
            if operator == "contains" and value not in log_value:
                return False
            elif operator == "equals" and value != log_value:
                return False
            elif operator == "regex" and not re.search(value, log_value):
                return False
        return True
    

    def _match_and_extract_conditions(self, conditions: List[Dict[str, str]], log: Dict[str, str]) -> List[str]:
        matched_keywords = []
    
        for condition in conditions:
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")
            log_value = log.get(field, "")

            if operator == "contains" and value in log_value:
                #print(f"[DEBUG rules_engine1] Evaluating rule condition: field={field}, operator={operator}, expected={value}, actual={log_value}")
                matched_keywords.append(f"{field} contains '{value}'")
            elif operator == "equals" and value == log_value:
                #print(f"[DEBUG rules_engine2] Evaluating rule condition: field={field}, operator={operator}, expected={value}, actual={log_value}")
                matched_keywords.append(f"{field} equals '{value}'")
            elif operator == "regex" and re.search(value, log_value):
                #print(f"[DEBUG rules_engine3] Evaluating rule condition: field={field}, operator={operator}, expected={value}, actual={log_value}")
                matched_keywords.append(f"{field} matches /{value}/")
            else:
                return []  # One condition failed, rule doesn't match

        return matched_keywords
 

 







RULES_DIR = os.path.join(os.path.dirname(__file__), "wazuh-ruleset", "rules")
sample_logs = extract_sample_logs_from_rules(RULES_DIR)
# Example usage
if __name__ == "__main__":
    from .rules_loader import load_rules
    print("Extracted log_types KRP", sample_logs)
    rules = load_rules(RULES_DIR)
    engine = RuleEngine(rules)
    if sample_logs:
        for sample_log in sample_logs:
            print("\nEvaluating sample log:", sample_log)
            matches = engine.match_log(sample_log)
            print("Matched Rules:", matches)
    else:
        print("No sample logs extracted.")
