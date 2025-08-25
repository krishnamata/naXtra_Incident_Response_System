from flask import Blueprint, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

mistral_bp = Blueprint('mistral', __name__)

# Load model once when the blueprint is registered
model_name = "mistralai/Mistral-7B-Instruct-v0.1"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(
    model_name, device_map="auto", torch_dtype=torch.float16
)

@mistral_bp.route('/generate_rule', methods=['POST'])
def generate_rule():
    data = request.get_json()
    prompt = data.get("prompt")

    if not prompt:
        return jsonify({"error": "Missing 'prompt' in request body"}), 400

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=512,
            pad_token_id=tokenizer.eos_token_id
        )

    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return jsonify({"prompt": prompt, "generated_rule": response})
