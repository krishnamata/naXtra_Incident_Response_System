# app/routes/ai_insights_routes.py
from flask import Blueprint, render_template, request, jsonify, session
from app.naxtraai.generator import generator
from app.cache import RULES_BY_ID, DECODERS_LOOKUP
from app.decoders.loader import apply_decoders

ai_insights_bp = Blueprint("ai_insights_bp", __name__, url_prefix="/ai_insights")

def is_authorized():
    # Example: session['role'] must be 'admin' or 'senior_analyst'
    return session.get('role') in ['admin', 'senior_analyst'] or request.headers.get('Role')=='admin'


@ai_insights_bp.route("/", methods=["GET"])
def insights_page():
    if not is_authorized():
        return "Access denied", 403
    return render_template("ai_insights.html")

@ai_insights_bp.route("/generate", methods=["POST"])
def generate_response():
    try:
        # --- Authorization check ---
        if not is_authorized():
            return jsonify({"status": "error", "message": "Access denied"}), 403

        data = request.get_json(force=True, silent=True) or {}
        text = data.get("text", "").strip()
        gen_type = data.get("gen_type", "general").lower()

        # --- Empty input check ---
        if not text:
            return jsonify({"status": "error", "message": "Empty input"}), 400

        # --- Generation logic ---
        if gen_type == "general":
            result = generator.generate(text, "general")

        elif gen_type == "decoder":
            parsed, decoder_obj = apply_decoders(text, DECODERS_LOOKUP)
            if decoder_obj:
                result = {"status": "exists", "name": getattr(decoder_obj, "name", None)}
            elif not generator.is_probable_log(text):
                result = generator.generate(text, "general")
            else:
                result = generator.generate(text, "decoder")

        elif gen_type == "rule":
            existing_rule = RULES_BY_ID.get(text)
            if existing_rule:
                result = {"status": "exists", "id": existing_rule.get("id")}
            elif not generator.is_probable_log(text):
                result = generator.generate(text, "general")
            else:
                result = generator.generate(text, "rule")

        else:
            result = {"status": "error", "message": f"Unknown gen_type: {gen_type}"}

    except Exception as e:
        result = {"status": "error", "message": f"Internal server error: {str(e)}"}

    # --- Ensure response is always JSON ---
    return jsonify(result)



