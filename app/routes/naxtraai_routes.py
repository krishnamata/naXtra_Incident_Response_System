# app/routes/naxtraai_routes.py
from flask import Blueprint, request, jsonify
from app.naxtraai.generator import generator
from app.cache import RULES_CACHE, RULES_BY_ID, RULES_KEYWORD_MAP
from app.cache import DECODERS_CACHE, DECODERS_LOOKUP
from app.decoders.loader import apply_decoders

naxtraai_bp = Blueprint("naxtraai_bp", __name__, url_prefix="/api/naxtraai")


@naxtraai_bp.route("/naxtraai_generate", methods=["POST"])
def naxtraai_generate():
    data = request.json
    log_text = data.get("log_text")
    gen_type = data.get("gen_type")

    if not log_text or not gen_type:
        return jsonify({"status": "error", "message": "Missing log_text or gen_type"}), 400

    log_lower = log_text.lower().strip()

    # --- Check existence for rule ---
    if gen_type == "rule":
        existing_rules = None
        for kw, rules in RULES_KEYWORD_MAP.items():
            if kw in log_lower or log_lower in kw:
                existing_rules = rules
                break

        if existing_rules:
            rule = existing_rules[0]  # pick the first matched rule
            return jsonify({
                "status": "exists",
                "id": rule.get("id"),
            })

    # --- Check existence for decoder ---
    elif gen_type == "decoder":
        # Try matching log with existing decoders
        parsed_log, decoder_obj = apply_decoders(log_text, DECODERS_CACHE)

        if decoder_obj:
            return jsonify({
                "status": "exists",
                "name": getattr(decoder_obj, "name", None),
             
            })


    # --- Generate new entry via AI ---
    result = generator.generate(log_text, gen_type)

    # --- Register in cache if newly generated ---
    if result.get("status") == "generated":
        if gen_type == "rule":
            RULES_BY_ID[result["id"]] = {"id": result.get("id"), "xml": result.get("data")}

        elif gen_type == "decoder":
            # Try to parse AI-generated decoder
            parsed_log, decoder_obj = apply_decoders(log_text, DECODERS_CACHE)
            if decoder_obj:
                DECODERS_LOOKUP[decoder_obj.name.lower()] = decoder_obj
            else:
                # fallback: store as dict if parsing fails
                DECODERS_LOOKUP[log_lower] = {"name": result.get("id"), "xml": result.get("data")}

    return jsonify(result)
