import logging
from logging.handlers import RotatingFileHandler
import os
import subprocess
import tempfile
import re
from flask import Blueprint, request, jsonify, stream_with_context, Response

from app.decoders.loader import DECODERS_CACHE, DECODERS_LOOKUP
from app.rules.rules_loader import RULES_CACHE, RULES_BY_ID, RULES_KEYWORD_MAP
from app.rules.rules_engine import RuleEngine
from app.naxtraai.generator import generator
from app.kb_indexer import KBIndex

# ------------------- Blueprint & Engine -------------------
naxtraai_bp = Blueprint('naxtraai', __name__)
rule_engine = RuleEngine(RULES_CACHE, RULES_BY_ID, RULES_KEYWORD_MAP)
kb_indexer = KBIndex()

# ------------------- Logger Setup -------------------
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
logger = logging.getLogger("xml_generation")
logger.setLevel(logging.INFO)
file_handler = RotatingFileHandler(
    os.path.join(log_dir, "generated_xml.log"),
    maxBytes=10*1024*1024,
    backupCount=5
)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# ------------------- Utility Functions -------------------
def extract_severity_from_log(log_text: str) -> int:
    match = re.search(r'severity\s*=\s*(\d+)', log_text, re.IGNORECASE)
    return int(match.group(1)) if match else 5

def clean_xml(xml_text: str) -> str:
    xml_text = xml_text.strip()
    start = xml_text.find('<')
    end = xml_text.rfind('>')
    if start == -1 or end == -1:
        return ""
    xml_fragment = xml_text[start:end+1]
    match = re.match(r'<(\w+)', xml_fragment)
    if match:
        root_tag = match.group(1)
        close_tag = f"</{root_tag}>"
        close_index = xml_fragment.rfind(close_tag)
        if close_index != -1:
            xml_fragment = xml_fragment[:close_index + len(close_tag)]
    return xml_fragment

def clean_generated_text(text: str) -> str:
    return re.sub(r"\[end of text\]$", "", text).strip()

def search_rule_in_files(log_text: str):
    if log_text in RULES_BY_ID:
        return RULES_BY_ID[log_text]
    log_lower = log_text.lower()
    for keyword, rules in RULES_KEYWORD_MAP.items():
        if keyword in log_lower:
            return rules[0] if rules else None
    return None

def search_decoder_in_files(log_text: str):
    decoder = DECODERS_LOOKUP.get(log_text.lower())
    if decoder:
        return decoder
    for dec in DECODERS_CACHE:
        if dec.matches({"message": log_text}):
            return dec
    return None

def validate_with_xmllint(xml_text: str) -> bool:
    """Validate XML using xmllint command line."""
    with tempfile.NamedTemporaryFile(mode='w+', suffix=".xml", delete=True) as tmpfile:
        tmpfile.write(xml_text)
        tmpfile.flush()
        try:
            result = subprocess.run(
                ['xmllint', '--noout', tmpfile.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"xmllint validation failed: {e}")
            return False

# ------------------- Streaming Generation -------------------
def stream_rule_decoder_generation(log_text: str, gen_type: str, max_retries=3):
    for attempt in range(1, max_retries + 1):
        try:
            result = generator.generate(log_text, gen_type)
        except RuntimeError as e:
            yield f"[ERROR] Failed to generate {gen_type} XML: {e}\n"
            return

        if result.get("status") == "exists":
            yield f"[INFO] Existing {gen_type} found: {result['data']}\n"
            break

        elif result.get("status") == "generated":
            generated_xml = result["data"]
            xml_type = gen_type if gen_type in ["rule", "decoder"] else None

            if xml_type:
                cleaned_xml = clean_xml(generated_xml)
                if not generator.id_manager.validate_xml_string(cleaned_xml, xml_type=xml_type):
                    yield f"[WARN] Attempt {attempt} - Failed internal schema validation. Retrying...\n"
                    logger.warning(
                        f"Attempt {attempt} - XML failed internal schema validation | Log: {log_text}\n{cleaned_xml}\n{'-'*80}"
                    )
                    continue

                if not validate_with_xmllint(cleaned_xml):
                    yield f"[WARN] Attempt {attempt} - XML failed xmllint validation. Retrying...\n"
                    logger.warning(
                        f"Attempt {attempt} - XML failed xmllint validation | Log: {log_text}\n{cleaned_xml}\n{'-'*80}"
                    )
                    continue

                for line in cleaned_xml.splitlines():
                    yield line + "\n"
                    logger.info(f"Type: {gen_type} | Log: {log_text} | XML chunk: {line}")
                yield f"\n[INFO] XML validated successfully after {attempt} attempt(s).\n"
                break

            else:  # general type
                yield generated_xml + "\n"
                break

        else:
            yield f"[ERROR] {result.get('message', 'Unknown error')}\n"
            break
    else:
        yield f"[ERROR] Failed to generate valid {gen_type} XML after {max_retries} attempts.\n"

# ------------------- Routes -------------------
@naxtraai_bp.route('/naxtraai_generate', methods=['POST'])
def naxtraai_generate():
    data = request.json or {}
    log_text = data.get('log_text', '').strip()
    gen_type = data.get('gen_type', 'general').lower()

    if gen_type in ['rule', 'decoder']:
        severity = extract_severity_from_log(log_text)
        if severity < 5:
            return jsonify({"answer": "Severity below 5; irrelevant for rule or decoder generation."})

        existing_rule = search_rule_in_files(log_text) if gen_type == 'rule' else None
        if existing_rule:
            return jsonify(
                {"answer": f"Existing rule found: ID={existing_rule.get('id')}, Title={existing_rule.get('title')}"}
            )

        existing_decoder = search_decoder_in_files(log_text) if gen_type == 'decoder' else None
        if existing_decoder:
            return jsonify({"answer": f"Existing decoder found: Name={existing_decoder.name}"})

        return Response(stream_with_context(stream_rule_decoder_generation(log_text, gen_type)),
                        mimetype='text/plain')

    else:  # general
        result = generator.generate(log_text, gen_type)
        if result.get("status") == "generated":
            output = clean_generated_text(result.get("data", ""))
        elif result.get("status") == "exists":
            output = result.get("data", "")
        else:
            output = f"[ERROR] {result.get('message', 'Unknown error')}"
        return jsonify({"answer": output})
