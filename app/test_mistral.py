from transformers import AutoModelForCausalLM, AutoTokenizer
import torch


def test_mistral():
    model_name = "mistralai/Mistral-7B-Instruct-v0.1"
    
    print("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    
    print("Loading model...")
    model = AutoModelForCausalLM.from_pretrained(model_name, device_map="auto", torch_dtype=torch.float16)
    
    prompt = "Explain the OSI 7 layers model in brief."
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    
    print("Generating response...")
    with torch.no_grad():
        outputs = model.generate(**inputs, max_new_tokens=512,temperature=0.7, top_p=0.95, do_sample=True, pad_token_id=tokenizer.eos_token_id)
    
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    print("\nGenerated text:\n", response)

if __name__ == "__main__":
    test_mistral()
