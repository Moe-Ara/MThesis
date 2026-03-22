from fastapi.testclient import TestClient

from reasoning_siem.api.app import create_app
from reasoning_siem.application.container import build_container


def test_api_feedback_and_trace_cycle(tmp_path):
    app = create_app()
    app.state.services = build_container(tmp_path)

    client = TestClient(app)

    triage_response = client.get("/api/triage")
    assert triage_response.status_code == 200
    incidents = triage_response.json()["incidents"]
    assert incidents

    incident_id = incidents[0]["incident_id"]

    incident_response = client.get(f"/api/incidents/{incident_id}")
    assert incident_response.status_code == 200

    feedback_response = client.post(
        f"/api/incidents/{incident_id}/feedback",
        json={"verdict": "fp", "severity_override": 1.0, "analyst": "test"},
    )
    assert feedback_response.status_code == 200
    payload = feedback_response.json()
    assert payload["after"]["risk_score"] <= payload["before"]["risk_score"]
    assert "weight_diff" in payload

    trace_response = client.post(
        f"/api/incidents/{incident_id}/trace",
        json={"action": "review_auth_logs", "analyst": "test"},
    )
    assert trace_response.status_code == 200
    recs = trace_response.json()["recommendations"]
    assert isinstance(recs, list)

    rec_response = client.get(f"/api/incidents/{incident_id}/recommendations")
    assert rec_response.status_code == 200
