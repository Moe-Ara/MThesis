import requests, json
messages = [
    {"role": "system", "content": "You are Wazuh detection engineer."},
    {"role": "user", "content": json.dumps({"detection_goal": "test", "example_events": [], "existing_rules": "<group></group>", "existing_logs": []})}
]
resp = requests.post("http://localhost:11434/api/chat", json={"model": "mistral", "messages": messages, "stream": False})
print(resp.status_code, resp.headers.get("content-type"))
print(resp.text[:1000])
