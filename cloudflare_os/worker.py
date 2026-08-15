"""Cloudflare Worker entrypoint (runs on Workers, not locally).

Serves the platform's public surface and routes every /gadgets/:id/* request
to the per-gadget `GadgetObject` Durable Object — the real "one instance per
gadget" primitive, same model as Cloudflare OS. The `x-user-id` header carries
the principal, exactly as in the local FastAPI app.

NOTE: Cloudflare's Python Workers bundler flattens modules to the bundle root
(worker.py, durable_object.py, domain/...), so this file and durable_object.py
use FLAT absolute imports that match that layout. The FastAPI app (main.py)
and its package-relative imports are used only for LOCAL runs (uvicorn/Docker)
and the pytest/behave gates — they are not part of the Worker bundle.

Routes:
  /api/health              -> {"status": "ok"}
  /gadgets/<id>/<route>    -> GadgetObject Durable Object (handles /api/<route>)
"""

from __future__ import annotations

from urllib.parse import urlparse

# The Durable Object class must be exported from the worker entrypoint for
# wrangler's `durable_objects.bindings[].class_name` to resolve it.
from durable_object import GadgetObject
from workers import Request, Response, WorkerEntrypoint

__all__ = ["Default", "GadgetObject"]


class Default(WorkerEntrypoint):
    async def fetch(self, request: Request) -> Response:
        url = urlparse(request.url)

        # Serve the static frontend (assets/ via the ASSETS binding) for the
        # root and any non-API path. The assets service handles /, favicon,
        # etc. itself.
        if not url.path.startswith("/api/") and not url.path.startswith("/gadgets/"):
            return await self.env.ASSETS.fetch(request)

        if url.path == "/api/health":
            return self._json({"status": "ok"})

        if url.path.startswith("/gadgets/"):
            return await self._route_gadget(request, url.path)

        return self._json({"error": "not found"}, 404)

    async def _route_gadget(self, request: Request, path: str) -> Response:
        # /gadgets/<id>/<route>  ->  GadgetObject explicit RPC method
        parts = path.strip("/").split("/")
        gadget_id = parts[1] if len(parts) > 1 else ""
        if not gadget_id:
            return self._json({"error": "missing gadget id"}, 400)

        do_id = self.env.GADGETS.idFromName(gadget_id)
        stub = self.env.GADGETS.get(do_id)

        user_id = request.headers.get("x-user-id")
        method = request.method
        rest = parts[2:]

        # Read the body as a plain JSON dict for RPC arguments.
        body: dict = {}
        if method != "GET":
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                body = {}

        try:
            if method == "GET" and rest == ["data"]:
                result = await stub.read_data(user_id)
            elif method == "POST" and rest == ["data"]:
                result = await stub.write_data(user_id, body.get("values", {}))
            elif method == "GET" and rest == ["meta"]:
                result = await stub.meta(user_id)
            elif method == "POST" and rest == ["init"]:
                result = await stub.init(body.get("name", "untitled"), body.get("app", "notes"), user_id)
            elif method == "POST" and rest == ["share"]:
                result = await stub.share(user_id, body.get("user_id", ""), body.get("role", "viewer"))
            elif method == "POST" and rest == ["revoke"]:
                result = await stub.revoke(user_id, body.get("user_id", ""))
            elif method == "POST" and rest == ["gatekeeper"]:
                result = await stub.request_approval(
                    user_id, body.get("action", ""), body.get("target", ""), body.get("payload", "")
                )
            elif method == "GET" and rest == ["approvals"]:
                result = await stub.list_approvals(user_id)
            elif method == "POST" and rest == ["approvals", "decide"]:
                result = await stub.decide_approval(user_id, body.get("id", ""), body.get("decision", ""))
            elif method == "GET" and rest == ["audit"]:
                result = await stub.audit(user_id)
            else:
                return self._json({"error": "not found"}, 404)

            return self._json(result.get("json", {}), result.get("status", 200))
        except Exception as exc:  # noqa: BLE001 - surface DO errors as 500
            return self._json({"error": str(exc)}, 500)

    @staticmethod
    def _json(payload: dict, status: int = 200) -> Response:
        import json

        return Response(json.dumps(payload), status=status, headers={"content-type": "application/json"})
