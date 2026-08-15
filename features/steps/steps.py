"""BDD step definitions — behave, per the academy notes' Gherkin workflow.

These drive the real platform API via TestClient, so the features are
"living documentation": when they pass, the platform behaves as specified.
"""

from __future__ import annotations

from behave import given, step, then, when
from fastapi.testclient import TestClient

from cloudflare_os.domain.gadget import MemoryStorage
from cloudflare_os.main import app
from cloudflare_os.storage import GadgetRegistry

client = TestClient(app)


def _reset() -> None:
    registry = GadgetRegistry()
    registry._storage = MemoryStorage()
    registry._services = {}
    from cloudflare_os import storage as storage_mod

    storage_mod.gadget_registry = registry


def _h(user_id: str | None) -> dict[str, str]:
    return {"x-user-id": user_id} if user_id else {}


# --- Given ---------------------------------------------------------------


@given('user "{owner}" owns a notes gadget "{gid}"')
def step_owner_has_gadget(context, owner: str, gid: str) -> None:
    _reset()
    context.gid = gid
    res = client.post(f"/gadgets/{gid}/init", json={"name": "Notes", "app": "notes"}, headers=_h(owner))
    assert res.status_code == 200, res.text
    context.owner = owner


@given('alice shares the gadget "{gid}" with "{user}" as "{role}"')
def step_share(context, gid: str, user: str, role: str) -> None:
    res = client.post(f"/gadgets/{gid}/share", json={"user_id": user, "role": role}, headers=_h(context.owner))
    assert res.status_code == 200, res.text


@given('alice requests approval to "{action}" to "{target}" with payload "{payload}"')
def step_request_approval(context, action: str, target: str, payload: str) -> None:
    res = client.post(
        f"/gadgets/{context.gid}/gatekeeper",
        json={"action": action, "target": target, "payload": payload},
        headers=_h(context.owner),
    )
    assert res.status_code == 200, res.text
    context.request_id = res.json()["approval"]["id"]


# --- When -----------------------------------------------------------------


@when('alice writes the note "{key}" with value "{value}"')
def step_write(context, key: str, value: str) -> None:
    context.last = client.post(
        f"/gadgets/{context.gid}/data", json={"values": {key: value}}, headers=_h(context.owner)
    )


@when('mallory tries to read the gadget "{gid}"')
def step_mallory_read(context, gid: str) -> None:
    context.last = client.get(f"/gadgets/{gid}/data", headers=_h("mallory"))


@when('an anonymous caller tries to read the gadget "{gid}"')
def step_anon_read(context, gid: str) -> None:
    context.last = client.get(f"/gadgets/{gid}/data", headers=_h(None))


@when('bob reads the gadget "{gid}"')
def step_bob_read(context, gid: str) -> None:
    context.last = client.get(f"/gadgets/{gid}/data", headers=_h("bob"))


@when('bob tries to write the note "{key}" with value "{value}"')
def step_bob_write(context, key: str, value: str) -> None:
    context.last = client.post(
        f"/gadgets/{context.gid}/data", json={"values": {key: value}}, headers=_h("bob")
    )


@when('bob tries to read the gadget "{gid}"')
def step_bob_read_again(context, gid: str) -> None:
    context.last = client.get(f"/gadgets/{gid}/data", headers=_h("bob"))


@when('alice asks the gatekeeper to "{action}" to "{target}" with payload "{payload}"')
def step_gatekeeper(context, action: str, target: str, payload: str) -> None:
    res = client.post(
        f"/gadgets/{context.gid}/gatekeeper",
        json={"action": action, "target": target, "payload": payload},
        headers=_h(context.owner),
    )
    assert res.status_code == 200, res.text
    context.last = res
    context.request_id = res.json()["approval"]["id"]


@when("alice approves the pending request")
def step_approve(context) -> None:
    context.last = client.post(
        f"/gadgets/{context.gid}/approvals/decide",
        json={"id": context.request_id, "decision": "approved"},
        headers=_h(context.owner),
    )


@when("mallory tries to approve the pending request")
def step_mallory_approve(context) -> None:
    context.last = client.post(
        f"/gadgets/{context.gid}/approvals/decide",
        json={"id": context.request_id, "decision": "approved"},
        headers=_h("mallory"),
    )


@step('alice revokes "{user}" from the gadget "{gid}"')
def step_revoke(context, user: str, gid: str) -> None:
    res = client.post(f"/gadgets/{gid}/revoke", json={"user_id": user}, headers=_h(context.owner))
    assert res.status_code == 200, res.text


# --- Then -----------------------------------------------------------------


@then('alice can read the note "{key}" and it equals "{value}"')
def step_read_note(context, key: str, value: str) -> None:
    res = client.get(f"/gadgets/{context.gid}/data", headers=_h(context.owner))
    assert res.status_code == 200
    assert res.json()["data"][key] == value


@then("the platform denies access with status 403")
def step_denied(context) -> None:
    assert context.last.status_code == 403, context.last.text


@then("bob can see the data")
def step_bob_sees(context) -> None:
    assert context.last.status_code == 200, context.last.text


@then('the action is queued as "{state}"')
def step_queued(context, state: str) -> None:
    assert context.last.status_code == 200
    assert context.last.json()["approval"]["state"] == state


@then('the audit log contains "{action}"')
def step_audit(context, action: str) -> None:
    res = client.get(f"/gadgets/{context.gid}/audit", headers=_h(context.owner))
    assert res.status_code == 200
    assert any(e["action"] == action for e in res.json()["audit"])


@then('the approval state is "{state}"')
def step_approval_state(context, state: str) -> None:
    assert context.last.status_code == 200
    assert context.last.json()["approval"]["state"] == state
