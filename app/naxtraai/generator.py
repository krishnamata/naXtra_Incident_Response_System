# app/naxtraai/generator.py
import subprocess
import re
from lxml import etree
from app.utils.unique_id_manager import UniqueIDManager
from app.kb_indexer import KBIndex
from app.cache import RULES_BY_ID, DECODERS_LOOKUP  # import your caches
from app.decoders.loader import apply_decoders  # if needed


class NaXtraAIGenerator:
    def __init__(self, kb_indexer: KBIndex, model_path: str, llama_cpp_path: str):
        self.kb_indexer = kb_indexer
        self.model_path = model_path
        self.llama_cpp_path = llama_cpp_path
        self.id_manager = UniqueIDManager(kb_indexer)

        # Reference existing caches
        self.rules_cache = RULES_BY_ID        # log_text -> {id, xml}
        self.decoders_cache = DECODERS_LOOKUP  # log_text -> {name, xml}

    def generate(self, log_text: str, gen_type: str):
        """
        Generate rule, decoder, or general output.
        Checks cache before generating new XML.
        """
        sanitized_text = log_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # Pre-check: non-log statements or questions
        if gen_type in ["rule", "decoder"] and not self.is_probable_log(sanitized_text):
            return {
                "status": "error",
                "message": "Input does not appear to be a log entry. XML generation not possible."
            }

        # --- Rule generation ---
        if gen_type == "rule":
            existing = self.rules_cache.get(sanitized_text)
            if existing:
                return {"status": "exists", "id": existing["id"], "data": existing["xml"]}

            unique_id = self.id_manager.get_next_id("r")
            xml_string = self._run_mistral(sanitized_text, gen_type, unique_id)
            xml_with_id = self._insert_unique_id(xml_string, gen_type, unique_id)
            self.rules_cache[sanitized_text] = {"id": unique_id, "xml": xml_with_id}

            return {"status": "generated", "id": unique_id, "data": xml_with_id}

        # --- Decoder generation ---
        elif gen_type == "decoder":
            existing = self.decoders_cache.get(sanitized_text)
            if existing:
                return {"status": "exists", "name": existing.get("name"), "data": existing["xml"]}

            unique_id = self.id_manager.get_next_id("d")
            xml_string = self._run_mistral(sanitized_text, gen_type, unique_id)
            xml_with_name = self._insert_unique_id(xml_string, gen_type, unique_id)
            decoder_name = self._extract_decoder_name(xml_with_name) or f"decoder_{unique_id}"

            self.decoders_cache[sanitized_text] = {"name": decoder_name, "xml": xml_with_name}
            return {"status": "generated", "name": decoder_name, "data": xml_with_name}

        # --- General query ---
        elif gen_type == "general":
            return self._generate_general(sanitized_text)

        else:
            return {"status": "error", "data": f"Unknown gen_type: {gen_type}"}

    # ---------------- Mistral XML Generation ----------------
    def _run_mistral(self, log_text: str, gen_type: str, unique_id: str):
        """
        Run Mistral (via llama-cli) to generate rule/decoder XML.
        """
        prompt = ""
        if gen_type == "rule":
            prompt = f"""
Generate a Wazuh rule XML for the following log:
{log_text}

Requirements:
- Output ONLY XML inside <ruleset> ... </ruleset>
- Include <rule id="unique_number" level="X"> with:
    <description>Brief description</description>
    <group>group_name</group>
- Do NOT echo the log inside <rule> tags
- Use a valid numeric ID (use {unique_id} for this rule)
"""
        elif gen_type == "decoder":
            prompt = f"""
Generate a Wazuh decoder XML for the following log:
{log_text}

Requirements:
- Output ONLY XML inside <decoders> ... </decoders>
- Include <decoder name="decoder_name"> with:
    <program_name>if applicable</program_name>
    <regex>pattern matching the log</regex>
- Do NOT wrap the log text inside XML tags
- Name the decoder based on log context
"""

        for attempt in range(3):
            try:
                result = subprocess.run(
                    [
                        self.llama_cpp_path,
                        "--model", self.model_path,
                        "--prompt", prompt,
                        "--n-predict", "512"
                    ],
                    capture_output=True,
                    text=True,
                    check=True
                )
                return result.stdout.strip()
            except subprocess.CalledProcessError:
                continue

        raise RuntimeError(f"Failed to generate {gen_type} XML after 3 attempts.")

    # ---------------- General Queries ----------------
    def _generate_general(self, log_text: str):
        """
        Dynamic LLM response for general queries.
        """
        prompt = f"Answer dynamically about cybersecurity context:\n{log_text}"
        try:
            result = subprocess.run(
                [
                    self.llama_cpp_path,
                    "--model", self.model_path,
                    "--prompt", prompt,
                    "--n-predict", "256"
                ],
                capture_output=True,
                text=True,
                check=True
            )
            answer = result.stdout.strip()
            return {"status": "generated", "data": answer}
        except subprocess.CalledProcessError:
            return {"status": "error", "data": "LLM failed to generate output."}

    # ---------------- Heuristic Log Check ----------------
    @staticmethod
    def is_probable_log(text: str) -> bool:
        """
        Returns True if text looks like a log entry, False if it's a normal sentence/question.
        """
        text = text.strip()
        log_patterns = [
            r'\d{4}-\d{2}-\d{2}',       # date YYYY-MM-DD
            r'\d{2}:\d{2}:\d{2}',       # time HH:MM:SS
            r'pid\s*[:=]\s*\d+',        # PID
            r'(ERROR|WARN|INFO|DEBUG)', # log levels
            r'\b[A-Z0-9_]+\b.*:',       # uppercase component names
            r'\w+=\S+'                  # key=value
        ]
        for pattern in log_patterns:
            if re.search(pattern, text):
                return True
        return False

    # ---------------- Insert ID / Name ----------------
    def _insert_unique_id(self, xml_string: str, gen_type: str, unique_id: str):
        """
        Insert the unique_id into the XML's main tag for rules or assign name for decoders.
        """
        try:
            root = etree.fromstring(xml_string.encode())

            if gen_type == "rule" and root.tag == "ruleset":
                rule_elem = root.find("rule")
                if rule_elem is not None:
                    rule_elem.set("id", unique_id)

            elif gen_type == "decoder" and root.tag == "decoders":
                dec_elem = root.find("decoder")
                if dec_elem is not None:
                    if "name" not in dec_elem.attrib or not dec_elem.attrib["name"]:
                        dec_elem.set("name", f"decoder_{unique_id}")

            return etree.tostring(root, pretty_print=True).decode()
        except Exception:
            return xml_string

    # ---------------- Extract Decoder Name ----------------
    def _extract_decoder_name(self, xml_string: str):
        try:
            root = etree.fromstring(xml_string.encode())
            dec_elem = root.find("decoder")
            if dec_elem is not None:
                return dec_elem.get("name")
        except Exception:
            pass
        return None


# -------------------- INSTANCE --------------------
kb_indexer = KBIndex()
generator = NaXtraAIGenerator(
    kb_indexer=kb_indexer,
    model_path="/var/www/modular-soar/mistral-7b-instruct-v0.1.Q4_K_M.gguf",
    llama_cpp_path="/home/kali/llama.cpp/build/bin/llama-cli"
)
