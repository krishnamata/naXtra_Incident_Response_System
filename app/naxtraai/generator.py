# app/naxtraai/generator.py
import subprocess
import re
from lxml import etree
import torch
from sentence_transformers import SentenceTransformer
from app.utils.unique_id_manager import UniqueIDManager
from app.kb_indexer import KBIndex
from app.cache import RULES_BY_ID, DECODERS_LOOKUP
from app.decoders.loader import apply_decoders

class NaXtraAIGeneratorRAG:
    def __init__(self, kb_indexer: KBIndex, model_path: str, llama_cpp_path: str, device: str = "cuda:0"):
        self.kb_indexer = kb_indexer
        self.model_path = model_path
        self.llama_cpp_path = llama_cpp_path
        self.id_manager = UniqueIDManager(kb_indexer)
        self.rules_cache = RULES_BY_ID
        self.decoders_cache = DECODERS_LOOKUP

        # --- RAG setup ---
        self.rag_texts = []
        self.rag_meta = []
        self.device = device
        self.embed_model = SentenceTransformer(
            "/home/kali/.cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2/snapshots/c9745ed1d9f207416be6d2e6f8de32d1f16199bf",
            device="cpu",
            local_files_only=True
        )


        self.rag_embeddings = None

    # ---------------- Core Generate ----------------
    def generate(self, log_text: str, gen_type: str):
        sanitized_text = log_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        if gen_type in ["rule", "decoder"] and not self.is_probable_log(sanitized_text):
            return {"status": "error", "message": "Input does not appear to be a log entry."}

        # --- Rule ---
        if gen_type == "rule":
            existing = self.rules_cache.get(sanitized_text)
            if existing:
                return {"status": "exists", "id": existing["id"], "data": existing["xml"]}

            unique_id = self.id_manager.get_next_id("r")
            xml_string = self._run_mistral(sanitized_text, gen_type, unique_id)
            xml_with_id = self._insert_unique_id(xml_string, gen_type, unique_id)
            self.rules_cache[sanitized_text] = {"id": unique_id, "xml": xml_with_id}

            # --- Incremental RAG update ---
            self.add_to_rag_index(xml_with_id, {"type": "rule", "id": unique_id})

            return {"status": "generated", "id": unique_id, "data": xml_with_id}

        # --- Decoder ---
        elif gen_type == "decoder":
            existing = self.decoders_cache.get(sanitized_text)
            if existing:
                return {"status": "exists", "name": existing.get("name"), "data": existing["xml"]}

            unique_id = self.id_manager.get_next_id("d")
            xml_string = self._run_mistral(sanitized_text, gen_type, unique_id)
            xml_with_name = self._insert_unique_id(xml_string, gen_type, unique_id)
            decoder_name = self._extract_decoder_name(xml_with_name) or f"decoder_{unique_id}"

            self.decoders_cache[sanitized_text] = {"name": decoder_name, "xml": xml_with_name}

            # --- Incremental RAG update ---
            self.add_to_rag_index(xml_with_name, {"type": "decoder", "name": decoder_name})

            return {"status": "generated", "name": decoder_name, "data": xml_with_name}

        # --- General query ---
        elif gen_type == "general":
            return self._generate_general(sanitized_text)

        else:
            return {"status": "error", "data": f"Unknown gen_type: {gen_type}"}

    # ---------------- Run Mistral ----------------
    def _run_mistral(self, log_text: str, gen_type: str, unique_id: str):
        prompt = ""
        if gen_type == "rule":
            prompt = f"Generate Wazuh rule XML for log:\n{log_text}\nID={unique_id}"
        elif gen_type == "decoder":
            prompt = f"Generate Wazuh decoder XML for log:\n{log_text}"

        for _ in range(3):
            try:
                result = subprocess.run(
                    [self.llama_cpp_path, "--model", self.model_path, "--prompt", prompt, "--n-predict", "512"],
                    capture_output=True, text=True, check=True
                )
                return result.stdout.strip()
            except subprocess.CalledProcessError:
                continue
        raise RuntimeError(f"Failed to generate {gen_type} XML after 3 attempts.")

    # ---------------- General queries ----------------
    def _generate_general(self, log_text: str):
        prompt = f"Answer dynamically about cybersecurity:\n{log_text}"
        try:
            result = subprocess.run(
                [self.llama_cpp_path, "--model", self.model_path, "--prompt", prompt, "--n-predict", "256"],
                capture_output=True, text=True, check=True
            )
            return {"status": "generated", "data": result.stdout.strip()}
        except subprocess.CalledProcessError:
            return {"status": "error", "data": "LLM failed."}

    # ---------------- RAG functions ----------------
    def add_to_rag_index(self, xml_text: str, meta: dict):
        self.rag_texts.append(xml_text)
        self.rag_meta.append(meta)
        emb = self.embed_model.encode(xml_text, convert_to_tensor=True, device=self.device)
        if self.rag_embeddings is None:
            self.rag_embeddings = emb.unsqueeze(0)
        else:
            self.rag_embeddings = torch.vstack([self.rag_embeddings, emb.unsqueeze(0)])

    # ---------------- Utilities ----------------
    @staticmethod
    def is_probable_log(text: str) -> bool:
        text = text.strip()
        patterns = [r'\d{4}-\d{2}-\d{2}', r'\d{2}:\d{2}:\d{2}', r'pid\s*[:=]\d+', r'(ERROR|WARN|INFO|DEBUG)', r'\w+=\S+']
        return any(re.search(p, text) for p in patterns)

    def _insert_unique_id(self, xml_string: str, gen_type: str, unique_id: str):
        try:
            root = etree.fromstring(xml_string.encode())
            if gen_type == "rule" and root.tag == "ruleset":
                rule_elem = root.find("rule")
                if rule_elem is not None:
                    rule_elem.set("id", unique_id)
            elif gen_type == "decoder" and root.tag == "decoders":
                dec_elem = root.find("decoder")
                if dec_elem is not None and not dec_elem.attrib.get("name"):
                    dec_elem.set("name", f"decoder_{unique_id}")
            return etree.tostring(root, pretty_print=True).decode()
        except Exception:
            return xml_string

    def _extract_decoder_name(self, xml_string: str):
        try:
            root = etree.fromstring(xml_string.encode())
            dec_elem = root.find("decoder")
            if dec_elem is not None:
                return dec_elem.get("name")
        except Exception:
            return None

# ---------------- INSTANCE ----------------
kb_indexer = KBIndex()
generator = NaXtraAIGeneratorRAG(
    kb_indexer=kb_indexer,
    model_path="/opt/llm/models/mistral-7b-instruct-v0.1.Q4_K_M.gguf",
    llama_cpp_path="/home/kali/llama.cpp/build/bin/llama-cli"
)

