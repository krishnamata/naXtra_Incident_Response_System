# kb_indexer.py

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

class KBIndex:
    def __init__(self, embedding_model_name='all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(embedding_model_name)
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

    def query(self, query_text, top_k=5):
        query_emb = self.model.encode([query_text], convert_to_numpy=True)
        faiss.normalize_L2(query_emb)
        D, I = self.index.search(query_emb, top_k)
        results = []
        for i in I[0]:
            if i < len(self.texts):
                results.append(self.texts[i])
        return results

    def get_all_rule_ids(self):
        # Assuming each entry in self.texts has an 'id' field
        return [entry.get('id') for entry in self.texts if 'id' in entry]

    def get_all_decoder_ids(self):
        # Assuming decoder entries also stored in self.texts with 'id' field
        return [entry.get('id') for entry in self.texts if 'id' in entry and entry.get('type') == 'decoder']


    def get_all_rule_names(self):
        # Assuming 'title' or 'name' holds the rule name; adjust accordingly
        return [entry.get('title') or entry.get('name') for entry in self.texts if 'title' in entry or 'name' in entry]

    def get_all_decoder_names(self):
        # Adjust 'title' or 'name' key as per your data structure for decoder names
        return [
            entry.get('title') or entry.get('name')
            for entry in self.texts
            if entry.get('type') == 'decoder' and ('title' in entry or 'name' in entry)
        ]
    # app/kb_indexer.py (add this to the class KBIndex)
    def lookup(self, log_text, gen_type):
        """
        Lookup existing KB entries matching log_text for rules or decoders.
        Returns the top match if similarity > threshold, else None.
        """
        if self.index is None:
            return None

        results = self.query(log_text, top_k=1)
        if not results:
            return None

    # Optional: add similarity threshold if you store it
        top_result = results[0]
        if gen_type == "rule" and top_result.get("type") == "rule":
            return top_result
        elif gen_type == "decoder" and top_result.get("type") == "decoder":
            return top_result
        return None

