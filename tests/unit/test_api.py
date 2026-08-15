"""API tests for the platform Worker (FastAPI TestClient)."""

from fastapi.testclient import TestClient

from cloudflare_os.main import app

client = TestClient(app)

# Reset the process-local registry between tests so state never leaks.
import cloudflare_os.storage as storage_mod  # noqa: E402


def _reset() -> None:
    storage_mod.gadget_registry._storage = storage_mod.MemoryStorage()
    storage_mod.gadget_registry._services = {}


def _headers(user_id: str) -> dict[str, str]:
    return {"x-user-id": user_id}


def test_health() -> None:
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_full_flow_init_write_read() -> None:
    _reset()
    gid = "g-flow"
    assert client.post(f"/gadgets/{gid}/init", json={"name": "Notes", "app": "notes"}, headers=_headers("alice")).status_code == 200
    assert client.post(f"/gadgets/{gid}/data", json={"values": {"title": "TDD"}}, headers=_headers("alice")).status_code == 200
    res = client.get(f"/gadgets/{gid}/data", headers=_headers("alice"))
    assert res.json()["data"] == {"title": "TDD"}


def test_stranger_gets_403() -> None:
    _reset()
    gid = "g-sec"
    client.post(f"/gadgets/{gid}/init", json={"name": "Private", "app": "notes"}, headers=_headers("alice"))
    res = client.get(f"/gadgets/{gid}/data", headers=_headers("mallory"))
    assert res.status_code == 403


def test_anonymous_gets_403() -> None:
    _reset()
    gid = "g-anon"
    client.post(f"/gadgets/{gid}/init", json={"name": "Private", "app": "notes"}, headers=_headers("alice"))
    res = client.get(f"/gadgets/{gid}/data")
    assert res.status_code == 403


def test_gatekeeper_requires_approval() -> None:
    _reset()
    gid = "g-gate"
    client.post(f"/gadgets/{gid}/init", json={"name": "Notes", "app": "notes"}, headers=_headers("alice"))
    res = client.post(f"/gadgets/{gid}/gatekeeper", json={"action": "post", "target": "twitter", "payload": "hi"}, headers=_headers("alice"))
    assert res.status_code == 200
    assert res.json()["approval"]["state"] == "pending"
