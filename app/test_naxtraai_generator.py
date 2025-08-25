from app.naxtraai.generator import generate_response

if __name__ == "__main__":
    prompt = "Generate a Wazuh rule for failed SSH login attempts."
    print("Calling generate_response() ...")
    result = generate_response(prompt)
    print("\nResult:\n", result)
