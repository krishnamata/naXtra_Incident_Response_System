from flask import Blueprint, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
import traceback

mistral_bp = Blueprint('mistral', __name__)

model_name = "mistralai/Mistral-7B-Instruct-v0.1"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name, device_map="auto", torch_dtype=torch.float16)

@mistral_bp.route('/generate_rule', methods=['POST])
def generate_rule():
    try:
        data = request.get_json(force=True)
        prompt = data.get("prompt")
        print("[DEBUG] Prompt received:", prompt)

        if not prompt:
            return jsonify({"error": "Missing 'prompt' in request body"}), 400

        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

        print("[INFO] Starting generation")
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=512,
                pad_token_id=tokenizer.eos_token_id
            )
        print("[INFO] Finished generation")

        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        print(f"[DEBUG] Received prompt: {prompt}")
        print("[DEBUG] Generated response length:", len(response))
        return jsonify({"prompt": prompt, "generated_rule": response})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
