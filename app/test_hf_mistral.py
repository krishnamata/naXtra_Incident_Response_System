from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

model_name = "~/models/mistral-7b/mistral-7b-instruct-v0.1.Q4_K_M.gguf"
tokenizer_name = "mistralai/Mistral-7B-Instruct-v0.1"

tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)
model = AutoModelForCausalLM.from_pretrained(model_name)

generator = pipeline("text-generation", model=model, tokenizer=tokenizer, device=0)  # change device as needed

def generate_text(prompt: str, max_length=100):
    outputs = generator(prompt, max_length=max_length, do_sample=True)
    return outputs[0]["generated_text"]

if __name__ == "__main__":
    prompt = input("Enter prompt: ")
    print(generate_text(prompt))
