# kb_indexer.py

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer




class KBIndex:
    def __init__(self, embedding_model_name='/home/kali/.cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2/snapshots/c9745ed1d9f207416be6d2e6f8de32d1f16199bf', device='cpu'):
        # Use local_files_only to prevent any internet download
        self.model = SentenceTransformer(embedding_model_name, device=device, local_files_only=True)
        self.texts = []   # Store raw text and metadata
        self.index = None

    def build_index(self, kb_entries):
        """
        kb_entries: list of dicts with 'text', 'id', 'type', 'metadata'
        """
        self.texts = kb_entries
        embeddings = self.model.encode([entry['text'] for entry in kb_entries], convert_to_numpy=True)
        dim = embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dim)  # Inner product for cosine similarity
        faiss.normalize_L2(embeddings)
        self.index.add(embeddings)

    def query(self, query_text, top_k=5, min_similarity=0.5):
        """
        Returns top_k KB entries and their similarity scores for a query.
        Only returns entries with similarity >= min_similarity.
        """
        if self.index is None or not self.texts:
            return []

        query_emb = self.model.encode([query_text], convert_to_numpy=True)
        faiss.normalize_L2(query_emb)
        D, I = self.index.search(query_emb, top_k)

        results = []
        for idx, score in zip(I[0], D[0]):
            if idx < len(self.texts) and score >= min_similarity:
                entry = self.texts[idx].copy()
                entry['similarity'] = float(score)
                results.append(entry)
        return results

    def lookup(self, log_text, gen_type, min_similarity=0.5):
        """
        Lookup existing KB entries matching log_text for rules or decoders.
        Returns the top match if similarity >= min_similarity, else None.
        """
        if self.index is None:
            return None

        results = self.query(log_text, top_k=1, min_similarity=min_similarity)
        if not results:
            return None

        top_result = results[0]
        if gen_type == "rule" and top_result.get("type") == "rule":
            return top_result
        elif gen_type == "decoder" and top_result.get("type") == "decoder":
            return top_result
        return None

    # --- Helper methods ---

    def get_all_rule_ids(self):
        return [entry.get('id') for entry in self.texts if 'id' in entry]

    def get_all_decoder_ids(self):
        return [entry.get('id') for entry in self.texts if 'id' in entry and entry.get('type') == 'decoder']

    def get_all_rule_names(self):
        return [entry.get('title') or entry.get('name') for entry in self.texts if 'title' in entry or 'name' in entry]

    def get_all_decoder_names(self):
        return [
            entry.get('title') or entry.get('name')
            for entry in self.texts
            if entry.get('type') == 'decoder' and ('title' in entry or 'name' in entry)
        ]
