"""Learn mode module - tracks accessed endpoints and entities."""

import json
import logging
import re
from typing import Any

import httpx

from .config import WhitelistConfig

logger = logging.getLogger(__name__)

# Regex patterns for extracting entity IDs from paths
ENTITY_PATH_PATTERNS = [
    re.compile(r"^/api/states/([a-z_]+\.[a-z0-9_]+)$"),  # /api/states/{entity_id}
    re.compile(r"^/api/history/period/[^/]+\?.*entity_id=([a-z_]+\.[a-z0-9_]+)"),  # History API
]


class Learner:
    """Tracks API endpoints and entities accessed during learn mode."""

    def __init__(self, whitelist: WhitelistConfig):
        self.whitelist = whitelist
        self._request_count = 0
        self._save_interval = 10  # Save every N requests

    def _normalize_endpoint(self, path: str) -> str:
        """
        Normalize an endpoint path by replacing specific IDs with placeholders.

        Examples:
            /api/states/sensor.temp -> /api/states/{entity_id}
            /api/services/light/turn_on -> /api/services/{domain}/{service}
        """
        # Entity state endpoint
        if re.match(r"^/api/states/[a-z_]+\.[a-z0-9_]+$", path):
            return "/api/states/{entity_id}"

        # Service call endpoint
        match = re.match(r"^/api/services/([a-z_]+)/([a-z_]+)$", path)
        if match:
            return "/api/services/{domain}/{service}"

        # Camera proxy endpoint
        if re.match(r"^/api/camera_proxy/[a-z_]+\.[a-z0-9_]+$", path):
            return "/api/camera_proxy/{entity_id}"

        # History endpoint with timestamp
        if re.match(r"^/api/history/period/\d{4}-\d{2}-\d{2}", path):
            return "/api/history/period/{timestamp}"

        # Logbook endpoint with timestamp
        if re.match(r"^/api/logbook/\d{4}-\d{2}-\d{2}", path):
            return "/api/logbook/{timestamp}"

        return path

    def _extract_entity_from_path(self, path: str) -> str | None:
        """Extract entity ID from URL path if present."""
        for pattern in ENTITY_PATH_PATTERNS:
            match = pattern.match(path)
            if match:
                return match.group(1)
        return None

    def _extract_ids_from_json(
        self,
        data: Any,
        entities: set[str],
        devices: set[str],
        areas: set[str],
    ) -> None:
        """Recursively extract entity, device, and area IDs from JSON data."""
        if isinstance(data, dict):
            # Check for entity_id field
            if "entity_id" in data:
                entity_id = data["entity_id"]
                if isinstance(entity_id, str) and "." in entity_id:
                    entities.add(entity_id)
                elif isinstance(entity_id, list):
                    for eid in entity_id:
                        if isinstance(eid, str) and "." in eid:
                            entities.add(eid)

            # Check for device_id field
            if "device_id" in data:
                device_id = data["device_id"]
                if isinstance(device_id, str) and device_id:
                    devices.add(device_id)
                elif isinstance(device_id, list):
                    for did in device_id:
                        if isinstance(did, str) and did:
                            devices.add(did)

            # Check for area_id field
            if "area_id" in data:
                area_id = data["area_id"]
                if isinstance(area_id, str) and area_id:
                    areas.add(area_id)
                elif isinstance(area_id, list):
                    for aid in area_id:
                        if isinstance(aid, str) and aid:
                            areas.add(aid)

            # Recurse into nested structures
            for value in data.values():
                self._extract_ids_from_json(value, entities, devices, areas)

        elif isinstance(data, list):
            for item in data:
                self._extract_ids_from_json(item, entities, devices, areas)

    def learn_from_request(self, path: str, query: str | None = None) -> None:
        """Learn from an incoming request path."""
        # Log full path with query for debugging
        if query:
            logger.debug(f"Request: {path}?{query}")

        normalized = self._normalize_endpoint(path)
        if self.whitelist.add_endpoint(normalized):
            logger.info(f"Learned new endpoint: {normalized}")

        # Extract entity from path
        entity_id = self._extract_entity_from_path(path)
        if entity_id and self.whitelist.add_entity(entity_id):
            logger.info(f"Learned new entity from path: {entity_id}")

    def learn_from_response(self, response: httpx.Response) -> None:
        """Learn entity, device, and area IDs from response body."""
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            return

        try:
            data = response.json()
        except json.JSONDecodeError:
            return

        entities: set[str] = set()
        devices: set[str] = set()
        areas: set[str] = set()
        self._extract_ids_from_json(data, entities, devices, areas)

        for entity_id in entities:
            if self.whitelist.add_entity(entity_id):
                logger.info(f"Learned new entity from response: {entity_id}")

        for device_id in devices:
            if self.whitelist.add_device(device_id):
                logger.info(f"Learned new device from response: {device_id}")

        for area_id in areas:
            if self.whitelist.add_area(area_id):
                logger.info(f"Learned new area from response: {area_id}")

    def learn_from_websocket_message(self, message: str) -> None:
        """Learn entity, device, and area IDs from a WebSocket message."""
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            return

        entities: set[str] = set()
        devices: set[str] = set()
        areas: set[str] = set()
        self._extract_ids_from_json(data, entities, devices, areas)

        for entity_id in entities:
            if self.whitelist.add_entity(entity_id):
                logger.info(f"Learned new entity from WebSocket: {entity_id}")

        for device_id in devices:
            if self.whitelist.add_device(device_id):
                logger.info(f"Learned new device from WebSocket: {device_id}")

        for area_id in areas:
            if self.whitelist.add_area(area_id):
                logger.info(f"Learned new area from WebSocket: {area_id}")

    def maybe_save(self) -> None:
        """Save whitelist periodically based on request count."""
        self._request_count += 1
        if self._request_count >= self._save_interval:
            self.save()
            self._request_count = 0

    def save(self) -> None:
        """Force save the whitelist to disk."""
        logger.info(
            f"Saving whitelist: {len(self.whitelist.endpoints)} endpoints, "
            f"{len(self.whitelist.entities)} entities, "
            f"{len(self.whitelist.devices)} devices, "
            f"{len(self.whitelist.areas)} areas"
        )
        self.whitelist.save()
