"""Process-local gadget registry.

In a real Cloudflare OS deployment this is replaced by Durable Object
bindings (one DO instance per gadget id). For the demo the registry gives
each gadget its own GadgetService with shared MemoryStorage.
"""

from __future__ import annotations

from .domain.gadget import MemoryStorage
from .gadget_service import GadgetService


class GadgetRegistry:
    def __init__(self) -> None:
        self._storage = MemoryStorage()
        self._services: dict[str, GadgetService] = {}

    def get_or_create(self, gadget_id: str) -> GadgetService:
        if gadget_id not in self._services:
            # Do NOT mint a record here — ownership is established by the
            # platform's /init call, so the first caller becomes the owner.
            self._services[gadget_id] = GadgetService(gadget_id=gadget_id, storage=self._storage)
        return self._services[gadget_id]


gadget_registry = GadgetRegistry()
