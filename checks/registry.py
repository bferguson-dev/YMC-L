"""Self-registering compliance check registry."""

from __future__ import annotations

import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class _CheckRegistry:
    def __init__(self):
        self._registry: dict[str, Callable] = {}
        self._dedup_groups: dict[str, list[str]] = {}
        self._check_ids_by_fn: dict[str, list[str]] = {}

    def register(
        self,
        *check_ids: str,
        dedup_group: Optional[str] = None,
    ) -> Callable:
        def decorator(fn: Callable) -> Callable:
            for check_id in check_ids:
                if check_id in self._registry:
                    logger.warning(
                        "Check ID %s is already registered to %s. Overwriting with %s.",
                        check_id,
                        self._registry[check_id].__name__,
                        fn.__name__,
                    )
                self._registry[check_id] = fn

            fn_ids = self._check_ids_by_fn.setdefault(fn.__name__, [])
            for check_id in check_ids:
                if check_id not in fn_ids:
                    fn_ids.append(check_id)

            if dedup_group:
                group = self._dedup_groups.setdefault(dedup_group, [])
                for check_id in check_ids:
                    if check_id not in group:
                        group.append(check_id)

            fn._check_ids = list(check_ids)
            fn._dedup_group = dedup_group
            return fn

        return decorator

    def get(self, check_id: str) -> Optional[Callable]:
        return self._registry.get(check_id)

    def is_dedup_secondary(self, check_id: str) -> bool:
        for group in self._dedup_groups.values():
            if check_id in group:
                return check_id != group[0]
        return False

    def all_check_ids(self) -> list[str]:
        return sorted(self._registry.keys())

    def summary(self) -> dict:
        return {fn: ids for fn, ids in sorted(self._check_ids_by_fn.items())}

    def __len__(self) -> int:
        return len(self._registry)

    def __contains__(self, check_id: str) -> bool:
        return check_id in self._registry


CheckRegistry = _CheckRegistry()
register_check = CheckRegistry.register
