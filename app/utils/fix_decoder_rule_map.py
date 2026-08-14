# app/utils/fix_decoder_rule_map.py
from app.decoders.loader import DECODERS_CACHE
from app.utils.decoder_log_rule import DECODER_RULE_MAP

def populate_decoder_rule_map():
    """
    Ensure each decoder has a mapping to rules for its log_type.
    This fills the gap where decoders exist but candidate rules are missing.
    """
    for decoder in DECODERS_CACHE:
        decoder_name = decoder.name
        # Skip if already mapped
        if decoder_name in DECODER_RULE_MAP:
            continue

        # Determine log_type based on decoder program_name or fallback
        log_type = decoder.program_name.lower() if decoder.program_name else "generic"

        # Create a generic always-match fallback rule if none exists
        rule_dict = {
            "id": f"GEN-{decoder_name.upper()}-001",
            "title": f"Fallback rule for decoder {decoder_name}",
            "enabled": True,
            "description": f"Automatically generated rule for decoder {decoder_name}",
            "detection": {"conditions": [{"always": True}]},
        }

        DECODER_RULE_MAP[decoder_name] = {log_type: [rule_dict]}

    print(f"[INFO] DECODER_RULE_MAP populated with {len(DECODER_RULE_MAP)} decoders.")

# --- Run the function at startup ---
populate_decoder_rule_map()
