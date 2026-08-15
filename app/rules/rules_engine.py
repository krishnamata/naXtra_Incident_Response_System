import re
from typing import List, Dict, Any
from app.utils.description_generator import generate_alert_description
from app.utils.log_type_registry import normalize_log_type
from app.utils.log_services_map import GROUP_TO_LOGTYPE, SERVICE_KEYWORDS


class RuleEngine:
    def __init__(self, rules, rules_by_id=None, keyword_map=None):
        self.rules = rules
        self.rules_by_id = rules_by_id or {}
        self.keyword_map = keyword_map or {}

    def exists_rule_id(self, rule_id):
        return rule_id in self.rules_by_id

    def exists_keyword(self, keyword):
        return keyword.lower() in self.keyword_map

    def match_log(self, log: Dict[str, Any], agent_type: str = None, debug=False) -> List[Dict[str, Any]]:
        """
        Match a single log entry against all loaded rules.
        Uses service-based log_type from decoder and falls back to normalized agent log types.
        """
        matched_rules = []

        # Use raw log_type for matching; fallback normalization
        service_log_type = log.get("log_type", "generic").lower()
        log_type = normalize_log_type(service_log_type, agent_type)

        if debug:
            print(f"Log message: {log.get('message')}")
            print(f"Normalized log type: {log_type}")

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            rule_log_types = [t.lower() for t in rule.get("log_types", [])]

            # --- SERVICE-BASED LOG TYPE MATCH ---
            if rule_log_types and log_type not in rule_log_types:
                # fallback: check if service maps to rule's log_types
                mapped_log_types = self._map_service_to_logtypes(service_log_type)
                if not set(mapped_log_types) & set(rule_log_types):
                    continue

            matched_keywords = self._match_and_extract_conditions(
                rule.get("detection", {}).get("conditions", []),
                log,
                log_type,
                agent_type
            )

            if matched_keywords:
                description = generate_alert_description(
                    rule.get("severity", 0),
                    mitre={
                        "technique_id": rule.get("technique_id", "NA"),
                        "technique__link": rule.get("technique_link", "NA"),
                        "tactic": rule.get("tactic", "NA")
                    },
                    matched_keywords=matched_keywords
                )

                matched_rule_info = {
                    "rule_id": rule.get("id", "NA"),
                    "title": rule.get("title", "No title"),
                    "severity": rule.get("severity", 0),
                    "description": description,
                    "technique_id": rule.get("technique_id", "NA"),
                    "technique_link": rule.get("technique_link", "NA"),
                    "matched_keywords": matched_keywords
                }

                matched_rules.append(matched_rule_info)

                if debug:
                    print(f"Matched rule: {rule.get('id')} -> {rule.get('title')}")
                    print(f"Matched keywords: {matched_keywords}")

        return matched_rules

    def _match_and_extract_conditions(
        self, conditions: List[Dict[str, Any]], log: Dict[str, Any],
        log_type: str = None, agent_type: str = None
    ) -> List[str]:
        """
        Evaluate rule conditions against the log.
        Returns list of matched keywords.
        """
        matched_keywords = []

        for condition in conditions:
            ctype = condition.get("type")

            if ctype == "field":
                field = condition.get("name")
                op = condition.get("operation")
                val = condition.get("value", "")
                log_val = log.get(field, "")

                if op == "contains" and val in log_val:
                    matched_keywords.append(f"{field} contains '{val}'")
                elif op == "equals" and val == log_val:
                    matched_keywords.append(f"{field} equals '{val}'")
                elif op == "regex":
                    try:
                        if re.search(val, log_val):
                            matched_keywords.append(f"{field} matches /{val}/")
                        else:
                            return []
                    except re.error:
                        return []
                else:
                    return []

            elif ctype == "match":
                val = condition.get("value", "")
                if val in log.get("message", ""):
                    matched_keywords.append(f"message contains '{val}'")
                else:
                    return []

            elif ctype == "regex":
                val = condition.get("value", "")
                try:
                    if re.search(val, log.get("message", "")):
                        matched_keywords.append(f"message matches /{val}/")
                    else:
                        return []
                except re.error:
                    return []

            elif ctype == "same_field":
                matched_keywords.append(f"same_field {condition.get('name')}")

            elif ctype == "same_source_ip":
                matched_keywords.append("same_source_ip condition matched")

            elif ctype == "if_sid":
                matched_keywords.append(f"if_sid {condition.get('sid')}")

            elif ctype == "if_group":
                matched_keywords.append(f"if_group {condition.get('group')}")

            elif ctype == "if_matched_group":
                matched_keywords.append(f"if_matched_group {condition.get('group')}")

            elif ctype == "frequency":
                matched_keywords.append(f"frequency {condition.get('value')}")

            elif ctype == "timeframe":
                matched_keywords.append(f"timeframe {condition.get('value')}")

            elif ctype == "same_location":
                matched_keywords.append("same_location condition matched")

            else:
                return []

        return matched_keywords

    def _map_service_to_logtypes(self, service_name: str) -> List[str]:
        """
        Map a service name (like 'sshd', 'nginx') to its log types using SERVICE_KEYWORDS or GROUP_TO_LOGTYPE.
        """
        service_name = service_name.lower()
        mapped = SERVICE_KEYWORDS.get(service_name, [])
        if not mapped:
            mapped = [GROUP_TO_LOGTYPE.get(service_name, "generic")]
        return mapped
