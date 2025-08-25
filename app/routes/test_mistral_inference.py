from transformers import AutoModelForCausalLM, AutoTokenizer

def test_mistral_inference():
    model_name = "mistralai/Mistral-7B-Instruct-v0.1"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name)

    prompt = "Hello, Mistral!"
    inputs = tokenizer(prompt, return_tensors="pt")
    outputs = model.generate(**inputs, max_length=20)
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    print("Mistral 7B response:", response)

if __name__ == "__main__":
    test_mistral_inference()
