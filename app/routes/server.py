from flask import Flask, jsonify, Blueprint, render_template
import json
import re

bp = Blueprint('server',__name__, template_folder='../templates')

def extract_json_from_log(filepath):
    with open(filepath, "r") as f:
        content = f.read()

    match = re.search(r"\{.*\}", content, re.DOTALL)
    if not match:
        return None

    json_text = match.group(0)
    try:
        data = json.loads(json_text)
        return data
    except json.JSONDecodeError:
        return None


@bp.route("/mistral-output")
def mistral_output_page():
    return render_template("mistral_output.html")


@bp.route("/api/mistral-output")
def mistral_output():
    data = extract_json_from_log("naxtraai_mistral_output.log")
    if data:
        return jsonify(data)
    else:
        return jsonify({"error": "Failed to parse JSON from log"}), 500

if __name__ == "__main__":
    app.run(debug=True)
