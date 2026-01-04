"""Tests for WebSocket message filtering."""

import json
import pytest

from ha_api_limiter.config import WhitelistConfig
from ha_api_limiter.ws_filter import WebSocketFilter


@pytest.fixture
def whitelist():
    """Create a whitelist with test entities, devices, and areas."""
    wl = WhitelistConfig()
    wl.endpoints = ["/api/states/{entity_id}"]
    wl.entities = [
        "light.living_room",
        "light.kitchen",
        "sensor.temperature",
        "sensor.weather_*",  # Wildcard pattern
    ]
    wl.devices = [
        "device_abc123",
        "device_def456",
    ]
    wl.areas = [
        "living_room",
        "kitchen",
    ]
    wl._compile_endpoint_patterns()
    return wl


@pytest.fixture
def ws_filter(whitelist):
    """Create a WebSocket filter with the test whitelist."""
    return WebSocketFilter(whitelist)


class TestBlockedMessageTypes:
    """Tests for blocked message types."""

    @pytest.mark.parametrize(
        "msg_type",
        [
            "render_template",
            "fire_event",
            "execute_script",
            "subscribe_trigger",
            "intent/handle",
        ],
    )
    def test_blocked_message_types(self, ws_filter, msg_type):
        """Test that dangerous message types are blocked."""
        message = json.dumps({"id": 1, "type": msg_type})
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed
        assert error is not None
        error_data = json.loads(error)
        assert error_data["success"] is False
        assert "not allowed" in error_data["error"]["message"]

    @pytest.mark.parametrize(
        "msg_type",
        [
            "config/automation/config/123",
            "config/script/config/456",
            "config/scene/config/789",
            "hassio/info",
            "backup/info",
            "config_entries/get",
        ],
    )
    def test_blocked_message_patterns(self, ws_filter, msg_type):
        """Test that blocked message patterns are rejected."""
        message = json.dumps({"id": 1, "type": msg_type})
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed
        assert error is not None

    @pytest.mark.parametrize(
        "msg_type",
        [
            "auth/current_user",
            "lovelace/config",
            "lovelace/resources",
        ],
    )
    def test_allowed_message_types_override_patterns(self, ws_filter, msg_type):
        """Test that explicitly allowed types override blocked patterns."""
        message = json.dumps({"id": 1, "type": msg_type})
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None


class TestSubscribeEvents:
    """Tests for subscribe_events validation."""

    def test_subscribe_events_without_event_type_blocked(self, ws_filter):
        """Test that subscribe_events without event_type is blocked."""
        message = json.dumps({"id": 1, "type": "subscribe_events"})
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed
        assert "requires event_type" in json.loads(error)["error"]["message"]

    @pytest.mark.parametrize(
        "event_type",
        [
            "state_changed",
            "component_loaded",
            "service_registered",
            "themes_updated",
            "entity_registry_updated",
        ],
    )
    def test_allowed_event_types(self, ws_filter, event_type):
        """Test that allowed event types are permitted."""
        message = json.dumps({"id": 1, "type": "subscribe_events", "event_type": event_type})
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None

    @pytest.mark.parametrize(
        "event_type",
        [
            "call_service",
            "automation_triggered",
            "script_started",
            "custom_event",
        ],
    )
    def test_blocked_event_types(self, ws_filter, event_type):
        """Test that non-allowed event types are blocked."""
        message = json.dumps({"id": 1, "type": "subscribe_events", "event_type": event_type})
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed
        assert "not allowed" in json.loads(error)["error"]["message"]


class TestBlockedServices:
    """Tests for blocked service calls."""

    @pytest.mark.parametrize(
        "domain,service",
        [
            ("homeassistant", "restart"),
            ("homeassistant", "stop"),
            ("automation", "trigger"),
            ("automation", "reload"),
            ("script", "turn_on"),
            ("shell_command", "anything"),
            ("python_script", "run"),
            ("notify", "mobile_app"),
        ],
    )
    def test_blocked_services(self, ws_filter, domain, service):
        """Test that dangerous services are blocked."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": domain,
                "service": service,
                "service_data": {"entity_id": "light.living_room"},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed
        assert "not allowed" in json.loads(error)["error"]["message"]


class TestEntityFiltering:
    """Tests for entity filtering in service calls."""

    def test_allowed_entity_in_service_data(self, ws_filter):
        """Test that whitelisted entity in service_data is allowed."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "light",
                "service": "turn_on",
                "service_data": {"entity_id": "light.living_room"},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None

    def test_allowed_entity_in_target(self, ws_filter):
        """Test that whitelisted entity in target is allowed."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "light",
                "service": "turn_on",
                "target": {"entity_id": "light.kitchen"},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None

    def test_blocked_entity_in_service_data(self, ws_filter):
        """Test that non-whitelisted entity in service_data is blocked."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "light",
                "service": "turn_on",
                "service_data": {"entity_id": "light.bedroom"},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed
        assert "not in whitelist" in json.loads(error)["error"]["message"]

    def test_blocked_entity_in_target(self, ws_filter):
        """Test that non-whitelisted entity in target is blocked."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "light",
                "service": "turn_on",
                "target": {"entity_id": "light.bedroom"},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed
        assert "not in whitelist" in json.loads(error)["error"]["message"]

    def test_wildcard_entity_match(self, ws_filter):
        """Test that wildcard patterns match entities."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "sensor",
                "service": "update",
                "service_data": {"entity_id": "sensor.weather_temperature"},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None

    def test_entity_list_in_service_data(self, ws_filter):
        """Test filtering with list of entities."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "light",
                "service": "turn_on",
                "service_data": {"entity_id": ["light.living_room", "light.kitchen"]},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None

    def test_mixed_entity_list_blocked(self, ws_filter):
        """Test that mixed list with non-whitelisted entity is blocked."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "light",
                "service": "turn_on",
                "service_data": {"entity_id": ["light.living_room", "light.bedroom"]},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed


class TestDeviceFiltering:
    """Tests for device filtering in service calls."""

    def test_allowed_device_in_target(self, ws_filter):
        """Test that whitelisted device in target is allowed."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "light",
                "service": "turn_on",
                "target": {"device_id": "device_abc123"},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None

    def test_blocked_device_in_target(self, ws_filter):
        """Test that non-whitelisted device in target is blocked."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "light",
                "service": "turn_on",
                "target": {"device_id": "device_unknown"},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed
        assert "Device not in whitelist" in json.loads(error)["error"]["message"]


class TestAreaFiltering:
    """Tests for area filtering in service calls."""

    def test_allowed_area_in_target(self, ws_filter):
        """Test that whitelisted area in target is allowed."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "light",
                "service": "turn_on",
                "target": {"area_id": "living_room"},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None

    def test_blocked_area_in_target(self, ws_filter):
        """Test that non-whitelisted area in target is blocked."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "light",
                "service": "turn_on",
                "target": {"area_id": "bedroom"},
            }
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed
        assert "Area not in whitelist" in json.loads(error)["error"]["message"]


class TestNoTargetBlocking:
    """Tests for blocking services without explicit targets."""

    @pytest.mark.parametrize(
        "domain",
        [
            "light",
            "switch",
            "cover",
            "fan",
            "climate",
            "media_player",
        ],
    )
    def test_entity_controlled_domain_requires_target(self, ws_filter, domain):
        """Test that entity-controlled domains require explicit targets."""
        message = json.dumps(
            {"id": 1, "type": "call_service", "domain": domain, "service": "turn_on"}
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert not allowed
        assert "requires explicit" in json.loads(error)["error"]["message"]

    def test_non_entity_domain_allows_no_target(self, ws_filter):
        """Test that non-entity domains can be called without targets."""
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "input_boolean",
                "service": "turn_on",
                "service_data": {"entity_id": "input_boolean.test"},
            }
        )
        # Note: This would need input_boolean in whitelist, but the point is
        # it checks entity, not requiring target for non-entity-controlled domains
        allowed, error = ws_filter.filter_client_message(message)
        # Will be blocked for entity, not for missing target
        assert not allowed


class TestResponseFiltering:
    """Tests for filtering server responses."""

    def test_filter_get_states_response(self, ws_filter):
        """Test filtering get_states response to only whitelisted entities."""
        # First, track the request
        request = json.dumps({"id": 1, "type": "get_states"})
        ws_filter.filter_client_message(request)

        # Now filter the response
        response = json.dumps(
            {
                "id": 1,
                "type": "result",
                "success": True,
                "result": [
                    {"entity_id": "light.living_room", "state": "on"},
                    {"entity_id": "light.bedroom", "state": "off"},
                    {"entity_id": "sensor.temperature", "state": "22"},
                ],
            }
        )
        filtered = ws_filter.filter_server_message(response)

        assert filtered is not None
        data = json.loads(filtered)
        assert len(data["result"]) == 2
        entity_ids = [e["entity_id"] for e in data["result"]]
        assert "light.living_room" in entity_ids
        assert "sensor.temperature" in entity_ids
        assert "light.bedroom" not in entity_ids

    def test_filter_device_registry_response(self, ws_filter):
        """Test filtering device registry response."""
        # Track the request
        request = json.dumps({"id": 1, "type": "config/device_registry/list"})
        ws_filter.filter_client_message(request)

        # Filter the response
        response = json.dumps(
            {
                "id": 1,
                "type": "result",
                "success": True,
                "result": [
                    {"id": "device_abc123", "name": "Device A"},
                    {"id": "device_unknown", "name": "Device B"},
                    {"id": "device_def456", "name": "Device C"},
                ],
            }
        )
        filtered = ws_filter.filter_server_message(response)

        assert filtered is not None
        data = json.loads(filtered)
        assert len(data["result"]) == 2
        device_ids = [d["id"] for d in data["result"]]
        assert "device_abc123" in device_ids
        assert "device_def456" in device_ids
        assert "device_unknown" not in device_ids

    def test_filter_area_registry_response(self, ws_filter):
        """Test filtering area registry response."""
        # Track the request
        request = json.dumps({"id": 1, "type": "config/area_registry/list"})
        ws_filter.filter_client_message(request)

        # Filter the response
        response = json.dumps(
            {
                "id": 1,
                "type": "result",
                "success": True,
                "result": [
                    {"area_id": "living_room", "name": "Living Room"},
                    {"area_id": "bedroom", "name": "Bedroom"},
                    {"area_id": "kitchen", "name": "Kitchen"},
                ],
            }
        )
        filtered = ws_filter.filter_server_message(response)

        assert filtered is not None
        data = json.loads(filtered)
        assert len(data["result"]) == 2
        area_ids = [a["area_id"] for a in data["result"]]
        assert "living_room" in area_ids
        assert "kitchen" in area_ids
        assert "bedroom" not in area_ids

    def test_filter_entity_registry_response(self, ws_filter):
        """Test filtering entity registry list_for_display response."""
        # Track the request
        request = json.dumps({"id": 1, "type": "config/entity_registry/list_for_display"})
        ws_filter.filter_client_message(request)

        # Filter the response
        response = json.dumps(
            {
                "id": 1,
                "type": "result",
                "success": True,
                "result": [
                    {"entity_id": "light.living_room", "name": "Living Room Light"},
                    {"entity_id": "light.bedroom", "name": "Bedroom Light"},
                    {"entity_id": "sensor.weather_temp", "name": "Weather Temp"},
                ],
            }
        )
        filtered = ws_filter.filter_server_message(response)

        assert filtered is not None
        data = json.loads(filtered)
        # light.living_room and sensor.weather_temp (matches sensor.weather_*)
        assert len(data["result"]) == 2


class TestEventFiltering:
    """Tests for filtering event messages."""

    def test_filter_state_changed_event_allowed(self, ws_filter):
        """Test that state_changed for whitelisted entity passes."""
        message = json.dumps(
            {
                "id": 1,
                "type": "event",
                "event": {
                    "event_type": "state_changed",
                    "data": {"entity_id": "light.living_room", "new_state": {"state": "on"}},
                },
            }
        )
        filtered = ws_filter.filter_server_message(message)

        assert filtered is not None
        assert filtered == message

    def test_filter_state_changed_event_blocked(self, ws_filter):
        """Test that state_changed for non-whitelisted entity is dropped."""
        message = json.dumps(
            {
                "id": 1,
                "type": "event",
                "event": {
                    "event_type": "state_changed",
                    "data": {"entity_id": "light.bedroom", "new_state": {"state": "on"}},
                },
            }
        )
        filtered = ws_filter.filter_server_message(message)

        assert filtered is None

    def test_filter_subscribe_entities_event(self, ws_filter):
        """Test filtering subscribe_entities events."""
        # First track the subscription
        request = json.dumps({"id": 5, "type": "subscribe_entities"})
        ws_filter.filter_client_message(request)

        # Now filter an event
        message = json.dumps(
            {
                "id": 5,
                "type": "event",
                "event": {
                    "a": {
                        "light.living_room": {"s": "on"},
                        "light.bedroom": {"s": "off"},
                    },
                    "c": {
                        "sensor.temperature": {"+": {"s": "23"}},
                        "sensor.secret": {"+": {"s": "42"}},
                    },
                },
            }
        )
        filtered = ws_filter.filter_server_message(message)

        assert filtered is not None
        data = json.loads(filtered)
        # Only whitelisted entities should remain
        assert "light.living_room" in data["event"]["a"]
        assert "light.bedroom" not in data["event"]["a"]
        assert "sensor.temperature" in data["event"]["c"]
        assert "sensor.secret" not in data["event"]["c"]


class TestMalformedMessages:
    """Tests for handling malformed messages."""

    def test_invalid_json_passes_through(self, ws_filter):
        """Test that invalid JSON passes through (HA handles it)."""
        message = "not valid json {"
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None

    def test_missing_type_passes_through(self, ws_filter):
        """Test that message without type passes through."""
        message = json.dumps({"id": 1, "data": "something"})
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None


class TestConfigOverrides:
    """Tests for configuration-based security overrides."""

    @pytest.fixture
    def whitelist_with_overrides(self):
        """Create a whitelist with security overrides."""
        wl = WhitelistConfig()
        wl.entities = ["light.living_room", "automation.test"]
        wl.devices = []
        wl.areas = []
        # Enable normally-blocked features
        wl.allowed_ws_types = ["render_template", "fire_event"]
        wl.allowed_event_types = ["automation_triggered", "custom_event"]
        wl.allowed_services = ["automation.trigger", "script.my_script"]
        wl._compile_endpoint_patterns()
        return wl

    @pytest.fixture
    def ws_filter_with_overrides(self, whitelist_with_overrides):
        """Create a filter with overrides."""
        return WebSocketFilter(whitelist_with_overrides)

    def test_allowed_ws_type_override(self, ws_filter_with_overrides):
        """Test that allowed_ws_types config enables blocked types."""
        # render_template is normally blocked, but enabled in config
        message = json.dumps(
            {"id": 1, "type": "render_template", "template": "{{ states('sensor.test') }}"}
        )
        allowed, error = ws_filter_with_overrides.filter_client_message(message)

        assert allowed
        assert error is None

    def test_allowed_ws_type_partial(self, ws_filter_with_overrides):
        """Test that only configured types are allowed."""
        # execute_script is NOT in allowed_ws_types, should still be blocked
        message = json.dumps({"id": 1, "type": "execute_script", "sequence": []})
        allowed, error = ws_filter_with_overrides.filter_client_message(message)

        assert not allowed

    def test_allowed_event_type_override(self, ws_filter_with_overrides):
        """Test that allowed_event_types config enables custom events."""
        # automation_triggered is normally blocked
        message = json.dumps(
            {"id": 1, "type": "subscribe_events", "event_type": "automation_triggered"}
        )
        allowed, error = ws_filter_with_overrides.filter_client_message(message)

        assert allowed
        assert error is None

    def test_allowed_service_override(self, ws_filter_with_overrides):
        """Test that allowed_services config enables blocked services."""
        # automation.trigger is normally blocked
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "automation",
                "service": "trigger",
                "service_data": {"entity_id": "automation.test"},
            }
        )
        allowed, error = ws_filter_with_overrides.filter_client_message(message)

        assert allowed
        assert error is None

    def test_allowed_service_specific(self, ws_filter_with_overrides):
        """Test that only specific allowed services work."""
        # script.turn_on is NOT in allowed_services (only script.my_script)
        message = json.dumps(
            {
                "id": 1,
                "type": "call_service",
                "domain": "script",
                "service": "turn_on",
                "service_data": {"entity_id": "script.test"},
            }
        )
        allowed, error = ws_filter_with_overrides.filter_client_message(message)

        assert not allowed

    def test_allowed_service_matches_exact(self, ws_filter_with_overrides):
        """Test that exact service match works."""
        message = json.dumps(
            {"id": 1, "type": "call_service", "domain": "script", "service": "my_script"}
        )
        allowed, error = ws_filter_with_overrides.filter_client_message(message)

        # Note: This passes the service check but would fail on entity check
        # if the domain requires targets. Scripts don't require entity targets.
        assert allowed

    def test_wildcard_service_override(self):
        """Test that wildcard service overrides work."""
        wl = WhitelistConfig()
        wl.entities = []
        wl.devices = []
        wl.areas = []
        wl.allowed_services = ["notify.*"]  # Allow all notify services
        wl._compile_endpoint_patterns()
        ws_filter = WebSocketFilter(wl)

        message = json.dumps(
            {"id": 1, "type": "call_service", "domain": "notify", "service": "mobile_app"}
        )
        allowed, error = ws_filter.filter_client_message(message)

        assert allowed
        assert error is None
