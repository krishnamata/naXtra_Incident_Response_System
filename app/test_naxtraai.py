from app.naxtraai.generator import generator

def test_generate():
    test_log = "Failed SSH login attempt from IP 192.168.1.100 at 2025-08-07T13:00:00"
    print("Sending test log to NaXtraAI...")
    output = generator.generate(test_log)
    print("\nNaXtraAI Output:\n", output)

if __name__ == "__main__":
    test_generate()
