from app.integrations.hybrid_analysis.client import search_by_hash

test_sha256 = "44d88612fea8a8f36de82e1278abb02f"  # Replace with a known sample

result = search_by_hash(test_sha256)
print("Hybrid Analysis result:", result)
