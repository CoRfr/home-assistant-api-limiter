"""Limit mode module - enforces whitelist restrictions."""

import logging
import re
from dataclasses import dataclass
from urllib.parse import parse_qs

from .config import WhitelistConfig

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    """Result of a whitelist check."""

    allowed: bool
    reason: str


class Limiter:
    """Enforces whitelist restrictions on incoming requests."""

    def __init__(self, whitelist: WhitelistConfig):
        self.whitelist = whitelist

    def _extract_entity_from_path(self, path: str) -> str | None:
        """Extract entity ID from state-related endpoints."""
        # /api/states/{entity_id}
        match = re.match(r"^/api/states/([a-z_]+\.[a-z0-9_]+)$", path)
        if match:
            return match.group(1)

        # /api/camera_proxy/{entity_id}
        match = re.match(r"^/api/camera_proxy/([a-z_]+\.[a-z0-9_]+)$", path)
        if match:
            return match.group(1)

        return None

    def _extract_entities_from_query(self, path: str, query: str) -> list[str]:
        """Extract entity IDs from query parameters for specific endpoints."""
        entities = []

        # /api/history/period/* - check filter_entity_id param
        if path.startswith("/api/history/period/"):
            params = parse_qs(query)
            filter_entities = params.get("filter_entity_id", [])
            for entity_list in filter_entities:
                # Can be comma-separated
                entities.extend(e.strip() for e in entity_list.split(",") if e.strip())

        # /api/logbook/* - check entity param
        elif path.startswith("/api/logbook/"):
            params = parse_qs(query)
            entity_params = params.get("entity", [])
            entities.extend(entity_params)

        return entities

    def check_request(self, path: str, method: str = "GET", query: str = "") -> CheckResult:
        """
        Check if a request is allowed by the whitelist.

        Args:
            path: The request path (e.g., /api/states/sensor.temp)
            method: HTTP method (currently not used for filtering)
            query: Query string (e.g., filter_entity_id=sensor.temp)

        Returns:
            CheckResult indicating if allowed and why
        """
        # Always allow health check
        if path == "/health":
            return CheckResult(allowed=True, reason="Health check endpoint")

        # Check if endpoint pattern is allowed
        if not self.whitelist.is_endpoint_allowed(path):
            logger.warning(f"Blocked endpoint: {path}")
            return CheckResult(
                allowed=False,
                reason=f"Endpoint not in whitelist: {path}",
            )

        # For entity-specific endpoints, also check entity whitelist
        entity_id = self._extract_entity_from_path(path)
        if entity_id:
            if not self.whitelist.is_entity_allowed(entity_id):
                logger.warning(f"Blocked entity: {entity_id}")
                return CheckResult(
                    allowed=False,
                    reason=f"Entity not in whitelist: {entity_id}",
                )

        # For endpoints with entity filtering in query params
        query_entities = self._extract_entities_from_query(path, query)
        for entity_id in query_entities:
            if not self.whitelist.is_entity_allowed(entity_id):
                logger.warning(f"Blocked entity in query: {entity_id}")
                return CheckResult(
                    allowed=False,
                    reason=f"Entity not in whitelist: {entity_id}",
                )

        return CheckResult(allowed=True, reason="Allowed by whitelist")
