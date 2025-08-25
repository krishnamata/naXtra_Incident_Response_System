import sys
import re
import subprocess
import json
import string
import os
from datetime import datetime
import xml.etree.ElementTree as ET

class NaXtraAIGenerator:
    def __init__(self, model_path: str, llama_cpp_path: str = "/home/kali/llama.cpp/build/bin/llama-cli"):
        self.model_path = model_path
        self.llama_cpp_path = llama_cpp_path

    def sanitize_text(self, text: str) -> str:
        allowed_chars = set(string.printable) | set(['{', '}', '"', '\\'])
        return ''.join(c for c in text if c in allowed_chars)

    @staticmethod
    def extract_json_from_log(filepath: str) -> dict:
        with open(filepath, "r") as f:
            content = f.read()

        match = re.search(r"\{.*\}", content, re.DOTALL)
        if not match:
            raise ValueError("No valid JSON object found in the file.")

        json_text = match.group(0)
        try:
            return json.loads(json_text)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON decode error: {e}")

    def extract_json(self, text: str) -> dict | None:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if not match:
            print("No JSON found in text.")
            return None
        json_text = match.group(0)
        try:
            return json.loads(json_text)
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            return None

    def _run_llama(self, prompt: str) -> str:
        cmd = [
            self.llama_cpp_path,
            "-m", self.model_path,
            "-p", prompt,
            "-n", "1024",
            "--temp", "0.7",
            "--top_k", "40"
        ]
        print("Running command:", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()

    def _extract_xml(self, text: str) -> str:
        match = re.search(r'(<rule[\s\S]*?</rule>|<decoder[\s\S]*?</decoder>)', text, re.DOTALL | re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _is_valid_xml(self, xml_content: str) -> bool:
        try:
            ET.fromstring(xml_content)
            return True
        except ET.ParseError:
            return False

    def generate(self, log_text: str) -> str:
        BASE_PROMPT = """
You are a security automation assistant for a SOAR platform.

Given the following user input, decide if it is:
- Raw log → Generate Wazuh-style decoder XML.
- Decoder XML → Validate & improve it.
- Rule request → Generate Wazuh-style rule XML.

Output requirements:
- Only output valid Wazuh XML.
- Do NOT include explanations, labels, or the prompt.
- XML must start with <rule> or <decoder> and end with </rule> or </decoder>.
- Follow official Wazuh XML tag structure.

User Input:
\"\"\"{user_input}\"\"\"
"""

        # First attempt
        final_prompt = BASE_PROMPT.format(user_input=log_text)
        raw_output = self._run_llama(final_prompt)

        # Save debug prompt and raw output
        with open("naxtraai_last_prompt.txt", "w") as f:
            f.write(final_prompt)
        with open("naxtraai_mistral_output.log", "w") as f:
            f.write(raw_output)

        # Extract XML
        cleaned_output = self._extract_xml(raw_output)

        # If invalid or missing, re-prompt strictly
        if not cleaned_output or not self._is_valid_xml(cleaned_output):
            print("⚠ Invalid XML detected. Retrying with stricter prompt...")
            strict_prompt = BASE_PROMPT + "\nSTRICT MODE: The output MUST be valid XML. No extra text. Output only the XML."
            raw_output = self._run_llama(strict_prompt.format(user_input=log_text))
            with open("naxtraai_retry_output.log", "w") as f:
                f.write(raw_output)
            cleaned_output = self._extract_xml(raw_output)

        # Final validation
        if not cleaned_output or not self._is_valid_xml(cleaned_output):
            print("❌ Failed to generate valid XML after retry.")
            return raw_output  # return whatever model produced for inspection

        # Save cleaned XML
        output_dir = "generated_outputs"
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(output_dir, f"output_{timestamp}.xml")
        with open(output_path, "w") as f:
            f.write(cleaned_output)

        print(f"✅ Generated valid XML saved to: {output_path}")
        return cleaned_output


# Adjust the model path accordingly
MODEL_PATH = "/home/kali/models/mistral-7b/mistral-7b-instruct-v0.1.Q4_K_M.gguf"
LLAMA_CLI_BINARY = "/home/kali/llama.cpp/build/bin/llama-cli"

# Global instance
generator = NaXtraAIGenerator(model_path=MODEL_PATH, llama_cpp_path=LLAMA_CLI_BINARY)

# Optional utility methods
def generate_response(prompt: str):
    return generator.generate(prompt)

def generate_xml_rule(prompt: str):
    return generator.generate(prompt)

def generate_decoder(prompt: str):
    return generator.generate(prompt)

def generate_rule_or_decoder(log_text: str):
    # You can customize logic if needed, or just call generate()
    return generator.generate(log_text)
