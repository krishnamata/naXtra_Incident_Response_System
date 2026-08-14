# app/cache.py

from app.rules.rules_loader import load_rules, build_rules_lookup
from app.decoders.loader import load_wazuh_decoders, build_decoder_lookup

# Load NaXtra rules and decoders
RULES_CACHE = load_rules("app/rules/wazuh-ruleset/rules")  # replace with actual path
RULES_BY_ID, RULES_KEYWORD_MAP = build_rules_lookup(RULES_CACHE)

DECODERS_CACHE = load_wazuh_decoders("/home/kali/wazuh-ruleset/decoders")  # replace with actual path
DECODERS_LOOKUP = build_decoder_lookup(DECODERS_CACHE)

PENDING_DECODERS = []  # list of dicts: {"name":..., "xml":..., "log_text":...}
PENDING_RULES = []     # similar structure for Wazuh rules
