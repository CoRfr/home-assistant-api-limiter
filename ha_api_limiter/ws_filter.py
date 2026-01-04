"""WebSocket message filtering for Home Assistant API."""

import json
import logging
import re
from typing import Any

from .config import WhitelistConfig

logger = logging.getLogger(__name__)


class WebSocketFilter:
    """Filters WebSocket messages based on entity whitelist."""

    # Message types that return entity lists that need filtering
    ENTITY_LIST_TYPES = {
        "get_states",
        "config/entity_registry/list",
        "config/entity_registry/list_for_display",
    }

    # Message types that return device lists that need filtering
    DEVICE_LIST_TYPES = {
        "config/device_registry/list",
    }

    # Message types that return area lists that need filtering
    AREA_LIST_TYPES = {
        "config/area_registry/list",
    }

    # Message types that return floor lists that need filtering
    FLOOR_LIST_TYPES = {
        "config/floor_registry/list",
    }

    # Subscription types that send entity data in events
    ENTITY_SUBSCRIPTION_TYPES = {
        "subscribe_entities",
    }

    # Message types that are completely blocked (security risk)
    BLOCKED_MESSAGE_TYPES = {
        "render_template",  # Can read any entity state via templates
        "fire_event",  # Can trigger automations indirectly
        "execute_script",  # Can execute arbitrary scripts
        "subscribe_trigger",  # Can subscribe to any entity's triggers
        "intent/handle",  # Voice command handling - can control entities
    }

    # Message type patterns that are blocked (for config access)
    BLOCKED_MESSAGE_PATTERNS = [
        re.compile(r"^config/automation/"),  # Automation config access
        re.compile(r"^config/script/"),  # Script config access
        re.compile(r"^config/scene/"),  # Scene config access
        re.compile(r"^config_entries/"),  # Config entries
        re.compile(r"^hassio/"),  # Supervisor access
        re.compile(r"^backup/"),  # Backup access
        re.compile(r"^auth/sign_path$"),  # URL signing (security risk)
        re.compile(r"^auth/refresh_token"),  # Token management
        re.compile(r"^auth/delete_refresh_token"),
    ]

    # Message types that are explicitly allowed (override blocked patterns)
    ALLOWED_MESSAGE_TYPES = {
        "auth/current_user",  # Needed for UI to show current user
        "lovelace/config",  # Needed for dashboard (entities filtered separately)
        "lovelace/resources",  # Needed for custom cards
    }

    # Dangerous services that should be blocked entirely
    BLOCKED_SERVICES = {
        # System control
        ("homeassistant", "restart"),
        ("homeassistant", "stop"),
        ("homeassistant", "reload_all"),
        ("homeassistant", "reload_core_config"),
        ("homeassistant", "reload_config_entry"),
        ("homeassistant", "set_location"),
        # Automation/script control (can affect non-whitelisted entities)
        ("automation", "trigger"),
        ("automation", "reload"),
        ("automation", "turn_on"),
        ("automation", "turn_off"),
        ("automation", "toggle"),
        ("script", "reload"),
        ("script", "turn_on"),
        ("script", "turn_off"),
        ("script", "toggle"),
        ("scene", "reload"),
        ("scene", "apply"),
        ("scene", "create"),
        # Input helpers (can be used to pass data)
        ("input_boolean", "reload"),
        ("input_number", "reload"),
        ("input_select", "reload"),
        ("input_text", "reload"),
        ("input_datetime", "reload"),
        ("input_button", "reload"),
        # Other dangerous services
        ("shell_command", "*"),  # Any shell command
        ("python_script", "*"),  # Any python script
        ("pyscript", "*"),  # Any pyscript
        ("rest_command", "*"),  # Any REST command
        ("notify", "*"),  # Notifications could leak info
        ("persistent_notification", "create"),
        ("system_log", "clear"),
        ("recorder", "purge"),
        ("recorder", "purge_entities"),
        ("recorder", "disable"),
        ("recorder", "enable"),
        ("logger", "set_level"),
        ("logger", "set_default_level"),
    }
    # Note: system_log.write is NOT blocked - it's used by frontend for error reporting

    # Services that require entity validation (domain -> requires entity check)
    ENTITY_CONTROLLED_DOMAINS = {
        "light",
        "switch",
        "cover",
        "fan",
        "climate",
        "media_player",
        "vacuum",
        "lock",
        "alarm_control_panel",
        "camera",
        "humidifier",
        "water_heater",
        "remote",
        "button",
        "number",
        "select",
        "siren",
        "text",
        "valve",
        "lawn_mower",
        "update",
    }

    # Allowed event types for subscribe_events
    ALLOWED_EVENT_TYPES = {
        "state_changed",  # Filtered by entity
        "component_loaded",  # Safe metadata
        "service_registered",  # Safe metadata
        "service_removed",  # Safe metadata
        "themes_updated",  # Safe UI metadata
        "panels_updated",  # Safe UI metadata
        "lovelace_updated",  # Safe UI metadata
        "core_config_updated",  # Safe config metadata
        "entity_registry_updated",  # Needed for UI entity updates (filtered separately)
        "device_registry_updated",  # Needed for UI device updates (filtered separately)
        "area_registry_updated",  # Needed for UI area updates (filtered separately)
        "floor_registry_updated",  # Needed for UI floor updates (filtered separately)
        "label_registry_updated",  # Safe metadata
        "repairs_issue_registry_updated",  # Safe metadata
    }

    def __init__(self, whitelist: WhitelistConfig):
        self.whitelist = whitelist
        # Track request types by message ID for filtering responses
        self._pending_requests: dict[int, str] = {}
        # Track subscription IDs that need event filtering
        self._entity_subscriptions: set[int] = set()

    def _extract_ids_from_target(
        self, data: dict[str, Any]
    ) -> tuple[list[str], list[str], list[str]]:
        """
        Extract entity, device, and area IDs from a call_service message.

        Checks both service_data and target fields.

        Returns:
            Tuple of (entity_ids, device_ids, area_ids)
        """
        entities: list[str] = []
        devices: list[str] = []
        areas: list[str] = []

        # Check both service_data and target for IDs
        for field in ["service_data", "target"]:
            container = data.get(field, {})
            if not isinstance(container, dict):
                continue

            # Extract entity_id
            entity_id = container.get("entity_id")
            if isinstance(entity_id, str):
                entities.append(entity_id)
            elif isinstance(entity_id, list):
                entities.extend(e for e in entity_id if isinstance(e, str))

            # Extract device_id
            device_id = container.get("device_id")
            if isinstance(device_id, str):
                devices.append(device_id)
            elif isinstance(device_id, list):
                devices.extend(d for d in device_id if isinstance(d, str))

            # Extract area_id
            area_id = container.get("area_id")
            if isinstance(area_id, str):
                areas.append(area_id)
            elif isinstance(area_id, list):
                areas.extend(a for a in area_id if isinstance(a, str))

        return entities, devices, areas

    def _is_service_blocked(self, domain: str, service: str) -> bool:
        """Check if a service is in the blocked list."""
        # Check config override first (user-allowed services)
        service_str = f"{domain}.{service}"
        if service_str in self.whitelist.allowed_services:
            return False
        # Check wildcard override (e.g., "automation.*")
        if f"{domain}.*" in self.whitelist.allowed_services:
            return False
        # Check exact match in block list
        if (domain, service) in self.BLOCKED_SERVICES:
            return True
        # Check wildcard match (domain, "*")
        if (domain, "*") in self.BLOCKED_SERVICES:
            return True
        return False

    def _is_message_type_blocked(self, msg_type: str) -> bool:
        """Check if a message type is blocked."""
        # Check config override first (user-allowed types)
        if msg_type in self.whitelist.allowed_ws_types:
            return False
        # Check explicit allow list (built-in safe types)
        if msg_type in self.ALLOWED_MESSAGE_TYPES:
            return False
        # Check explicit block list
        if msg_type in self.BLOCKED_MESSAGE_TYPES:
            return True
        # Check pattern blocks
        for pattern in self.BLOCKED_MESSAGE_PATTERNS:
            if pattern.match(msg_type):
                return True
        return False

    def _is_event_type_allowed(self, event_type: str) -> bool:
        """Check if an event type is allowed for subscribe_events."""
        # Check built-in allowed types
        if event_type in self.ALLOWED_EVENT_TYPES:
            return True
        # Check config override (user-allowed event types)
        if event_type in self.whitelist.allowed_event_types:
            return True
        return False

    def _create_error_response(self, msg_id: int, message: str) -> str:
        """Create a WebSocket error response."""
        return json.dumps(
            {
                "id": msg_id,
                "type": "result",
                "success": False,
                "error": {
                    "code": "not_allowed",
                    "message": message,
                },
            }
        )

    def filter_client_message(self, message: str) -> tuple[bool, str | None]:
        """
        Filter a message from client to Home Assistant.

        Args:
            message: Raw JSON message string

        Returns:
            Tuple of (allowed, error_response).
            If allowed is True, error_response is None.
            If allowed is False, error_response contains the JSON error to send back.
        """
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            # Let malformed messages pass through - HA will handle them
            return True, None

        msg_type = data.get("type")
        msg_id = data.get("id")

        logger.debug(f"Client WS message: type={msg_type}, id={msg_id}")

        # === SECURITY: Block dangerous message types ===
        if msg_type and self._is_message_type_blocked(msg_type):
            logger.warning(f"Blocked dangerous message type: {msg_type}")
            return False, self._create_error_response(
                msg_id, f"Message type not allowed: {msg_type}"
            )

        # === SECURITY: Validate subscribe_events ===
        if msg_type == "subscribe_events":
            event_type = data.get("event_type")
            if event_type is None:
                # Subscribing to ALL events is not allowed
                logger.warning("Blocked subscribe_events without event_type (subscribes to all)")
                return False, self._create_error_response(
                    msg_id, "subscribe_events requires event_type parameter"
                )
            if not self._is_event_type_allowed(event_type):
                logger.warning(f"Blocked subscribe_events for event_type: {event_type}")
                return False, self._create_error_response(
                    msg_id, f"Event type not allowed: {event_type}"
                )

        # Track requests that need response filtering
        if msg_type in self.ENTITY_LIST_TYPES and msg_id is not None:
            logger.info(f"Tracking entity request for filtering: id={msg_id}, type={msg_type}")
            self._pending_requests[msg_id] = msg_type

        # Track device requests that need response filtering
        if msg_type in self.DEVICE_LIST_TYPES and msg_id is not None:
            logger.info(f"Tracking device request for filtering: id={msg_id}, type={msg_type}")
            self._pending_requests[msg_id] = msg_type

        # Track area requests that need response filtering
        if msg_type in self.AREA_LIST_TYPES and msg_id is not None:
            logger.info(f"Tracking area request for filtering: id={msg_id}, type={msg_type}")
            self._pending_requests[msg_id] = msg_type

        # Track floor requests that need response filtering
        if msg_type in self.FLOOR_LIST_TYPES and msg_id is not None:
            logger.info(f"Tracking floor request for filtering: id={msg_id}, type={msg_type}")
            self._pending_requests[msg_id] = msg_type

        # Track entity subscriptions for event filtering
        if msg_type in self.ENTITY_SUBSCRIPTION_TYPES and msg_id is not None:
            logger.info(f"Tracking entity subscription: id={msg_id}, type={msg_type}")
            self._entity_subscriptions.add(msg_id)

        # === Filter call_service messages ===
        if msg_type != "call_service":
            return True, None

        domain = data.get("domain", "")
        service = data.get("service", "")

        # === SECURITY: Block dangerous services ===
        if self._is_service_blocked(domain, service):
            logger.warning(f"Blocked dangerous service: {domain}.{service}")
            return False, self._create_error_response(
                msg_id, f"Service not allowed: {domain}.{service}"
            )

        # Extract all target IDs (entities, devices, areas)
        entities, devices, areas = self._extract_ids_from_target(data)

        # === SECURITY: Validate entities ===
        blocked_entities = [e for e in entities if not self.whitelist.is_entity_allowed(e)]
        if blocked_entities:
            logger.warning(
                f"Blocked WebSocket call_service {domain}.{service} "
                f"for entities: {blocked_entities}"
            )
            return False, self._create_error_response(
                msg_id, f"Entity not in whitelist: {blocked_entities[0]}"
            )

        # === SECURITY: Validate devices ===
        blocked_devices = [d for d in devices if not self.whitelist.is_device_allowed(d)]
        if blocked_devices:
            logger.warning(
                f"Blocked WebSocket call_service {domain}.{service} "
                f"for devices: {blocked_devices}"
            )
            return False, self._create_error_response(
                msg_id, f"Device not in whitelist: {blocked_devices[0]}"
            )

        # === SECURITY: Validate areas ===
        blocked_areas = [a for a in areas if not self.whitelist.is_area_allowed(a)]
        if blocked_areas:
            logger.warning(
                f"Blocked WebSocket call_service {domain}.{service} " f"for areas: {blocked_areas}"
            )
            return False, self._create_error_response(
                msg_id, f"Area not in whitelist: {blocked_areas[0]}"
            )

        # === SECURITY: For entity-controlled domains, require explicit targets ===
        if domain in self.ENTITY_CONTROLLED_DOMAINS:
            if not entities and not devices and not areas:
                # No targets specified - this could affect ALL entities in the domain
                logger.warning(
                    f"Blocked WebSocket call_service {domain}.{service} "
                    f"with no explicit targets (would affect all {domain} entities)"
                )
                err = f"Service {domain}.{service} requires explicit targets"
                return False, self._create_error_response(msg_id, err)

        return True, None

    def _filter_entity_list(self, result: list[Any], request_type: str) -> list[Any]:
        """Filter a list of entities based on whitelist."""
        filtered = []
        for item in result:
            if not isinstance(item, dict):
                continue

            # get_states returns state objects with entity_id
            # entity_registry returns registry entries with entity_id
            entity_id = item.get("entity_id")
            if entity_id and self.whitelist.is_entity_allowed(entity_id):
                filtered.append(item)

        original_count = len(result)
        filtered_count = len(filtered)
        if original_count != filtered_count:
            logger.info(
                f"Filtered {request_type} response: "
                f"{filtered_count}/{original_count} entities allowed"
            )

        return filtered

    def _filter_device_list(self, result: list[Any], request_type: str) -> list[Any]:
        """Filter a list of devices based on whitelist."""
        filtered = []
        for item in result:
            if not isinstance(item, dict):
                continue

            # device_registry returns devices with id field
            device_id = item.get("id")
            if device_id and self.whitelist.is_device_allowed(device_id):
                filtered.append(item)

        original_count = len(result)
        filtered_count = len(filtered)
        if original_count != filtered_count:
            logger.info(
                f"Filtered {request_type} response: "
                f"{filtered_count}/{original_count} devices allowed"
            )

        return filtered

    def _filter_area_list(self, result: list[Any], request_type: str) -> list[Any]:
        """Filter a list of areas based on whitelist."""
        filtered = []
        for item in result:
            if not isinstance(item, dict):
                continue

            # area_registry returns areas with area_id field
            area_id = item.get("area_id")
            if area_id and self.whitelist.is_area_allowed(area_id):
                filtered.append(item)

        original_count = len(result)
        filtered_count = len(filtered)
        if original_count != filtered_count:
            logger.info(
                f"Filtered {request_type} response: {filtered_count}/{original_count} areas allowed"
            )

        return filtered

    def _filter_floor_list(self, result: list[Any], request_type: str) -> list[Any]:
        """Filter a list of floors - only show floors that contain whitelisted areas."""
        # If no areas are whitelisted, show no floors
        if not self.whitelist.areas:
            logger.info(
                f"Filtered {request_type} response: "
                f"0/{len(result)} floors allowed (no areas whitelisted)"
            )
            return []

        # For now, pass through all floors if any areas are whitelisted
        # A more sophisticated approach would check which floors contain whitelisted areas
        return result

    def _filter_subscribe_entities_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """
        Filter subscribe_entities event data.

        Format: {"a": {entity_id: state}, "c": {entity_id: state}, "r": [entity_id]}
        - a: additions (new entities)
        - c: changes (state changes)
        - r: removals
        """
        filtered_event = {}
        total_original = 0
        total_filtered = 0

        # Filter additions
        if "a" in event and isinstance(event["a"], dict):
            original = event["a"]
            total_original += len(original)
            filtered = {
                eid: state
                for eid, state in original.items()
                if self.whitelist.is_entity_allowed(eid)
            }
            total_filtered += len(filtered)
            if filtered:
                filtered_event["a"] = filtered

        # Filter changes
        if "c" in event and isinstance(event["c"], dict):
            original = event["c"]
            total_original += len(original)
            filtered = {
                eid: state
                for eid, state in original.items()
                if self.whitelist.is_entity_allowed(eid)
            }
            total_filtered += len(filtered)
            if filtered:
                filtered_event["c"] = filtered

        # Filter removals
        if "r" in event and isinstance(event["r"], list):
            original = event["r"]
            total_original += len(original)
            filtered = [eid for eid in original if self.whitelist.is_entity_allowed(eid)]
            total_filtered += len(filtered)
            if filtered:
                filtered_event["r"] = filtered

        if total_original != total_filtered:
            logger.debug(
                f"Filtered subscribe_entities event: {total_filtered}/{total_original} entities"
            )

        # Return None if nothing left to send
        if not filtered_event:
            return None

        return filtered_event

    def _filter_single_message(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """
        Filter a single message, potentially modifying result content.

        Returns the (possibly modified) message dict, or None if should be dropped entirely.
        """
        msg_type = data.get("type")
        msg_id = data.get("id")

        # Check if this is a response to a tracked request
        if msg_type == "result" and msg_id in self._pending_requests:
            request_type = self._pending_requests.pop(msg_id)
            result = data.get("result")

            if isinstance(result, list):
                # Filter based on request type
                if request_type in self.DEVICE_LIST_TYPES:
                    filtered_result = self._filter_device_list(result, request_type)
                elif request_type in self.AREA_LIST_TYPES:
                    filtered_result = self._filter_area_list(result, request_type)
                elif request_type in self.FLOOR_LIST_TYPES:
                    filtered_result = self._filter_floor_list(result, request_type)
                else:
                    filtered_result = self._filter_entity_list(result, request_type)
                # Return modified copy
                return {**data, "result": filtered_result}

            return data

        # Filter event messages
        if msg_type != "event":
            return data

        event = data.get("event", {})

        # Check if this is a subscribe_entities event (has a/c/r keys, no event_type)
        if msg_id in self._entity_subscriptions:
            # subscribe_entities events have format: {"a": {}, "c": {}, "r": []}
            if "a" in event or "c" in event or "r" in event:
                filtered_event = self._filter_subscribe_entities_event(event)
                if filtered_event is None:
                    return None
                return {**data, "event": filtered_event}
            # Initial result for subscribe_entities might also need filtering
            return data

        event_type = event.get("event_type")

        # Only filter state_changed events
        if event_type != "state_changed":
            return data

        event_data = event.get("data", {})
        entity_id = event_data.get("entity_id")

        if not entity_id:
            return data

        if not self.whitelist.is_entity_allowed(entity_id):
            logger.debug(f"Filtered state_changed event for entity: {entity_id}")
            return None

        return data

    def filter_server_message(self, message: str) -> str | None:
        """
        Filter a message from Home Assistant to client.

        Args:
            message: Raw JSON message string

        Returns:
            The message to forward, or None to drop it.
        """
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            # Let malformed messages pass through
            return message

        # HA can send batched messages as arrays
        if isinstance(data, list):
            filtered = []
            modified = False
            for msg in data:
                result = self._filter_single_message(msg)
                if result is None:
                    modified = True
                elif result is not msg:
                    filtered.append(result)
                    modified = True
                else:
                    filtered.append(msg)

            if not filtered:
                return None
            if not modified:
                return message  # Nothing filtered, return original
            return json.dumps(filtered)

        # Single message
        result = self._filter_single_message(data)
        if result is None:
            return None
        if result is not data:
            return json.dumps(result)
        return message
