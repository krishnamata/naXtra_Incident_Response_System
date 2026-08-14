# app/routes/mistral_api.py
from flask import Blueprint, request, jsonify
from app.naxtraai.generator import generator
import torch
from sentence_transformers import util

mistral_bp = Blueprint('mistral', __name__)

@mistral_bp.route('/generate_rule', methods=['POST'])
def generate_rule():
    data = request.get_json()
    prompt = data.get("prompt")
    gen_type = data.get("gen_type", "general")

    if not prompt:
        return jsonify({"error": "Missing 'prompt'"}), 400

    # --- Use RAG retrieval if embeddings exist ---
    context_texts = []
    if generator.rag_embeddings is not None:
        query_emb = generator.embed_model.encode(prompt, convert_to_tensor=True, device=generator.device)
        cos_scores = torch.nn.functional.cosine_similarity(query_emb.unsqueeze(0), generator.rag_embeddings)
        top_idx = torch.topk(cos_scores, k=min(5, len(generator.rag_texts))).indices
        context_texts = [generator.rag_texts[i] for i in top_idx]

    # Prepend RAG context to prompt
    if context_texts:
        rag_context = "\n".join(context_texts)
        prompt = f"Context:\n{rag_context}\n\nQuestion:\n{prompt}"

    result = generator.generate(prompt, gen_type)
    return jsonify(result)
