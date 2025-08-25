from app.integrations.threatfox.client import search_threatfox_by_hash

test_hash = "44d88612fea8a8f36de82e1278abb02f"  # Example MD5 hash (EICAR test file)
result = search_threatfox_by_hash(test_hash)

if result:
    print("ThreatFox data found:", result)
else:
    print("No data found in ThreatFox for the given hash.")
