from fastapi.testclient import TestClient

from artex_soar.api import create_app

H = {"X-API-Key": "secret", "X-SOAR-User": "alice"}


def test_api_flow(cfg, engine, sample_lines):
    client = TestClient(create_app(cfg, engine, api_key="secret"))
    assert client.get("/health").json()["mode"] == "dry_run"
    assert client.get("/api/v1/incidents").status_code == 401
    r = client.post("/api/v1/ingest/access-log?target=web01", content="".join(sample_lines), headers=H)
    assert r.status_code == 200 and len(r.json()["incidents"]) == 1
    inc_id = r.json()["incidents"][0]
    inc = client.get(f"/api/v1/incidents/{inc_id}", headers=H).json()
    assert inc["severity"] == "P1" and inc["actions"]
    pending = client.get("/api/v1/actions?status=pending_approval", headers=H).json()
    act = client.post(f"/api/v1/actions/{pending[0]['id']}/approve", headers=H).json()
    assert act["status"] == "dry_run" and act["approved_by"] == "alice"
    assert client.post(f"/api/v1/actions/{pending[0]['id']}/approve", headers=H).status_code == 409
    r = client.post(f"/api/v1/incidents/{inc_id}/status", json={"status": "closed"}, headers=H)
    assert r.json()["status"] == "closed"
    audit = client.get("/api/v1/audit", headers=H).json()
    assert any(a["actor"] == "alice" and a["event"] == "action_approved" for a in audit)
    assert "ARTEX SOAR" in client.get("/").text


def test_generic_events(cfg, engine):
    client = TestClient(create_app(cfg, engine, api_key="secret"))
    r = client.post("/api/v1/events", headers=H, json=[
        {"ts": "2026-11-24T10:00:00Z", "kind": "http", "source_ip": "198.51.100.20",
         "uri": "/x", "status": 404, "headers": {"X-Artex-Hook": "1"}}])
    assert r.status_code == 200 and r.json()["incidents"]
