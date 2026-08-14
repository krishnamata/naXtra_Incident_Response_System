# app/routes/naxtraai_routes.py
from flask import Blueprint, request, jsonify
from app.naxtraai.generator import generator
from app.cache import (
    RULES_BY_ID, RULES_KEYWORD_MAP,
    DECODERS_LOOKUP, DECODERS_CACHE,
    PENDING_RULES, PENDING_DECODERS
)
from app.decoders.loader import apply_decoders
import torch

naxtraai_bp = Blueprint("naxtraai_bp", __name__, url_prefix="/api/naxtraai")


@naxtraai_bp.route("/generate", methods=["POST"])
def naxtraai_generate():
    """
    Unified endpoint for generating:
    1. Wazuh rules
    2. Wazuh decoders
    3. General cybersecurity answers with RAG
    """
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Missing JSON body"}), 400

    log_text = data.get("log_text")
    gen_type = data.get("gen_type", "general").lower().strip()

    if not log_text:
        return jsonify({"status": "error", "message": "Missing 'log_text'"}), 400

    if gen_type not in ["rule", "decoder", "general"]:
        return jsonify({"status": "error", "message": f"Invalid gen_type: {gen_type}"}), 400

    log_lower = log_text.lower().strip()

    # ---------------- Check existence for rule ----------------
    if gen_type == "rule":
        existing_rules = None
        for kw, rules in RULES_KEYWORD_MAP.items():
            if kw in log_lower or log_lower in kw:
                existing_rules = rules
                break
        if existing_rules:
            rule = existing_rules[0]
            return jsonify({"status": "exists", "id": rule.get("id"), "data": rule.get("xml")})
        else:
            # AI generates new rule → add to pending
            try:
                result = generator.generate(log_text, gen_type)
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

            if result.get("status") == "generated":
                PENDING_RULES.append({
                    "id": result.get("id"),
                    "xml": result.get("data"),
                    "log_text": log_text
                })
                return jsonify({"status": "pending", "id": result.get("id"), "data": result.get("data")})

    # ---------------- Check existence for decoder ----------------
    elif gen_type == "decoder":
        parsed_log, decoder_obj = apply_decoders(log_text, DECODERS_CACHE)
        if decoder_obj:
            # Existing decoder → return exists
            DECODERS_LOOKUP[decoder_obj.name.lower()] = decoder_obj
            if decoder_obj not in DECODERS_CACHE:
                DECODERS_CACHE.append(decoder_obj)
            return jsonify({
                "status": "exists",
                "name": getattr(decoder_obj, "name", None),
                "data": getattr(decoder_obj, "xml", None)
            })
        else:
            # AI generates new decoder → add to pending
            try:
                result = generator.generate(log_text, gen_type)
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

            if result.get("status") == "generated":
                PENDING_DECODERS.append({
                    "name": result.get("name", result.get("id")),
                    "xml": result.get("data"),
                    "log_text": log_text
                })
                return jsonify({"status": "pending", "name": result.get("name"), "data": result.get("data")})

    # ---------------- Prepend RAG context for general queries ----------------
    if gen_type == "general" and getattr(generator, "rag_embeddings", None) is not None:
        try:
            query_emb = generator.embed_model.encode(
                log_text, convert_to_tensor=True, device=generator.device
            )
            cos_scores = torch.nn.functional.cosine_similarity(
                query_emb.unsqueeze(0), generator.rag_embeddings
            )
            top_idx = torch.topk(cos_scores, k=min(5, len(generator.rag_texts))).indices
            context_texts = [generator.rag_texts[i] for i in top_idx]
            if context_texts:
                rag_context = "\n".join(context_texts)
                log_text = f"Context:\n{rag_context}\n\nQuestion:\n{log_text}"
        except Exception:
            pass  # fallback to original log_text if RAG fails

    # ---------------- Generate new entry via AI for general ----------------
    try:
        result = generator.generate(log_text, gen_type)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify(result)


# ---------------- Optional endpoints to view pending items ----------------

@naxtraai_bp.route("/pending/decoders", methods=["GET"])
def view_pending_decoders():
    return jsonify(PENDING_DECODERS)


@naxtraai_bp.route("/pending/rules", methods=["GET"])
def view_pending_rules():
    return jsonify(PENDING_RULES)
