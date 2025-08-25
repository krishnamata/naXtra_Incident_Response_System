from datetime import datetime, timedelta
from app.utils.agent_heartbeat import AgentHeartbeat

def get_active_agents(timeout_seconds=600):
    threshold = datetime.utcnow() - timedelta(seconds=timeout_seconds)
    active_agents = AgentHeartbeat.query.filter(AgentHeartbeat.last_seen >= threshold).all()
    agent_dict = {}
    for hb in active_agents:
        os_key = hb.agent_name.lower()
        agent_dict[os_key] = agent_dict.get(os_key, 0) + 1
    return agent_dict
