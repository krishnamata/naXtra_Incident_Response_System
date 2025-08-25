# ai_assistant.py

def ai_suggest_rule_improvements(kb_index, new_log_sample):
    # Retrieve relevant rules and decoders based on the log sample
    candidates = kb_index.query(new_log_sample, top_k=5)
    
    # Build prompt for LLM
    prompt = "Given the following logs and existing detection rules/decoders, suggest improvements or new rules:\n"
    for c in candidates:
        prompt += f"- [{c['type']}] {c['text']}\n"
    prompt += f"New log sample: {new_log_sample}\n"
    prompt += "Suggest rule or decoder creation or highlight weaknesses.\n"

    # Call your LLM interface here (e.g., OpenAI or local model)
    # response = llm.generate(prompt)
    # return response

    return prompt  # Placeholder for demonstration
