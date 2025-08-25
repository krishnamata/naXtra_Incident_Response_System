# app/automation/dispatcher.py
import requests

def send_command_to_agent(agent_ip, payload):
    """
    Sends JSON payload to the agent's control endpoint.
    Assumes HTTPS with token authentication (extend as needed).
    """
    url = f"https://{agent_ip}:5443/api/control"  # Agent listens on secure channel
    headers = {
        "Authorization": "Bearer <your_shared_token>",
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5, verify=False)
        return response.status_code, response.json()
    except Exception as e:
        return 500, {"error": str(e)}

def isolate_system(agent_ip):
    """
    Send isolation command to agent to restrict all network access
    except communication with naXtraSOAR.
    """
    payload = {
        "action": "isolate",
        "allowlist": ["<naxtrasoar_ip>"]
    }
    return send_command_to_agent(agent_ip, payload)
