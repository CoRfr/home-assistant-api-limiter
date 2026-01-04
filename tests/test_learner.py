"""Tests for learn mode functionality."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ha_api_limiter.config import WhitelistConfig
from ha_api_limiter.learner import Learner


@pytest.fixture
def whitelist():
    """Create a whitelist for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.yaml"
        wl = WhitelistConfig(config_path)
        wl._compile_endpoint_patterns()
        yield wl


@pytest.fixture
def learner(whitelist):
    """Create a learner for testing."""
    return Learner(whitelist)


class TestEndpointNormalization:
    """Tests for endpoint path normalization."""

    def test_normalize_entity_state_endpoint(self, learner):
        """Test normalizing entity state endpoints."""
        path = "/api/states/sensor.temperature"
        normalized = learner._normalize_endpoint(path)
        assert normalized == "/api/states/{entity_id}"

    def test_normalize_service_call_endpoint(self, learner):
        """Test normalizing service call endpoints."""
        path = "/api/services/light/turn_on"
        normalized = learner._normalize_endpoint(path)
        assert normalized == "/api/services/{domain}/{service}"

    def test_normalize_camera_proxy_endpoint(self, learner):
        """Test normalizing camera proxy endpoints."""
        path = "/api/camera_proxy/camera.front_door"
        normalized = learner._normalize_endpoint(path)
        assert normalized == "/api/camera_proxy/{entity_id}"

    def test_normalize_history_endpoint(self, learner):
        """Test normalizing history endpoints."""
        path = "/api/history/period/2024-01-01T00:00:00"
        normalized = learner._normalize_endpoint(path)
        assert normalized == "/api/history/period/{timestamp}"

    def test_normalize_logbook_endpoint(self, learner):
        """Test normalizing logbook endpoints."""
        path = "/api/logbook/2024-01-01T00:00:00"
        normalized = learner._normalize_endpoint(path)
        assert normalized == "/api/logbook/{timestamp}"

    def test_normalize_unrecognized_endpoint(self, learner):
        """Test that unrecognized endpoints are returned as-is."""
        path = "/api/custom/endpoint"
        normalized = learner._normalize_endpoint(path)
        assert normalized == path


class TestEntityExtraction:
    """Tests for entity ID extraction from paths."""

    def test_extract_entity_from_states_path(self, learner):
        """Test extracting entity from states path."""
        path = "/api/states/sensor.temperature"
        entity = learner._extract_entity_from_path(path)
        assert entity == "sensor.temperature"

    def test_extract_entity_from_non_entity_path(self, learner):
        """Test that non-entity paths return None."""
        path = "/api/config"
        entity = learner._extract_entity_from_path(path)
        assert entity is None


class TestJSONExtraction:
    """Tests for extracting IDs from JSON data."""

    def test_extract_entity_id_string(self, learner):
        """Test extracting string entity_id."""
        data = {"entity_id": "light.living_room"}
        entities, devices, areas = set(), set(), set()
        learner._extract_ids_from_json(data, entities, devices, areas)

        assert "light.living_room" in entities
        assert len(devices) == 0
        assert len(areas) == 0

    def test_extract_entity_id_list(self, learner):
        """Test extracting list of entity_ids."""
        data = {"entity_id": ["light.living_room", "light.bedroom"]}
        entities, devices, areas = set(), set(), set()
        learner._extract_ids_from_json(data, entities, devices, areas)

        assert "light.living_room" in entities
        assert "light.bedroom" in entities

    def test_extract_device_id(self, learner):
        """Test extracting device_id."""
        data = {"device_id": "device123"}
        entities, devices, areas = set(), set(), set()
        learner._extract_ids_from_json(data, entities, devices, areas)

        assert "device123" in devices

    def test_extract_area_id(self, learner):
        """Test extracting area_id."""
        data = {"area_id": "living_room"}
        entities, devices, areas = set(), set(), set()
        learner._extract_ids_from_json(data, entities, devices, areas)

        assert "living_room" in areas

    def test_extract_nested_ids(self, learner):
        """Test extracting IDs from nested structures."""
        data = {
            "result": {"entity_id": "sensor.test", "device_id": "device123", "area_id": "kitchen"}
        }
        entities, devices, areas = set(), set(), set()
        learner._extract_ids_from_json(data, entities, devices, areas)

        assert "sensor.test" in entities
        assert "device123" in devices
        assert "kitchen" in areas

    def test_extract_from_list(self, learner):
        """Test extracting IDs from list of objects."""
        data = [
            {"entity_id": "light.one"},
            {"entity_id": "light.two"},
        ]
        entities, devices, areas = set(), set(), set()
        learner._extract_ids_from_json(data, entities, devices, areas)

        assert "light.one" in entities
        assert "light.two" in entities

    def test_skip_invalid_entity_ids(self, learner):
        """Test that invalid entity_ids (no domain) are skipped."""
        data = {"entity_id": "invalid_no_domain"}
        entities, devices, areas = set(), set(), set()
        learner._extract_ids_from_json(data, entities, devices, areas)

        assert len(entities) == 0


class TestLearnFromRequest:
    """Tests for learning from HTTP requests."""

    def test_learn_new_endpoint(self, learner, whitelist):
        """Test learning a new endpoint."""
        learner.learn_from_request("/api/config", None)
        assert "/api/config" in whitelist.endpoints

    def test_learn_entity_from_path(self, learner, whitelist):
        """Test learning entity from request path."""
        learner.learn_from_request("/api/states/sensor.temperature", None)
        assert "sensor.temperature" in whitelist.entities

    def test_learn_normalized_endpoint(self, learner, whitelist):
        """Test that endpoints are normalized before adding."""
        learner.learn_from_request("/api/states/sensor.test1", None)
        learner.learn_from_request("/api/states/sensor.test2", None)

        # Should only have one normalized endpoint
        normalized_count = sum(1 for e in whitelist.endpoints if e == "/api/states/{entity_id}")
        assert normalized_count == 1


class TestLearnFromResponse:
    """Tests for learning from HTTP responses."""

    def test_learn_from_json_response(self, learner, whitelist):
        """Test learning from JSON response body."""
        response = MagicMock()
        response.headers = {"content-type": "application/json"}
        response.json.return_value = {
            "entity_id": "light.discovered",
            "device_id": "device_abc",
            "area_id": "bedroom",
        }

        learner.learn_from_response(response)

        assert "light.discovered" in whitelist.entities
        assert "device_abc" in whitelist.devices
        assert "bedroom" in whitelist.areas

    def test_skip_non_json_response(self, learner, whitelist):
        """Test that non-JSON responses are skipped."""
        response = MagicMock()
        response.headers = {"content-type": "text/html"}

        learner.learn_from_response(response)

        assert len(whitelist.entities) == 0

    def test_handle_invalid_json(self, learner, whitelist):
        """Test handling of invalid JSON responses."""
        import json as json_module

        response = MagicMock()
        response.headers = {"content-type": "application/json"}
        response.json.side_effect = json_module.JSONDecodeError("Invalid", "", 0)

        # Should not raise
        learner.learn_from_response(response)
        assert len(whitelist.entities) == 0


class TestLearnFromWebSocket:
    """Tests for learning from WebSocket messages."""

    def test_learn_from_websocket_message(self, learner, whitelist):
        """Test learning from WebSocket message."""
        message = json.dumps(
            {
                "type": "event",
                "event": {
                    "entity_id": "sensor.ws_entity",
                    "device_id": "ws_device",
                    "area_id": "ws_area",
                },
            }
        )

        learner.learn_from_websocket_message(message)

        assert "sensor.ws_entity" in whitelist.entities
        assert "ws_device" in whitelist.devices
        assert "ws_area" in whitelist.areas

    def test_handle_invalid_websocket_json(self, learner, whitelist):
        """Test handling of invalid WebSocket JSON."""
        message = "not valid json {"

        # Should not raise
        learner.learn_from_websocket_message(message)
        assert len(whitelist.entities) == 0


class TestPeriodicSave:
    """Tests for periodic saving functionality."""

    def test_maybe_save_counts_requests(self, learner):
        """Test that maybe_save counts requests."""
        initial_count = learner._request_count
        learner.maybe_save()
        assert learner._request_count == initial_count + 1

    def test_maybe_save_triggers_at_interval(self, learner, whitelist):
        """Test that save is triggered at interval."""
        learner._save_interval = 3
        learner._request_count = 0

        # Mock save
        save_called = []
        original_save = whitelist.save
        whitelist.save = lambda: save_called.append(True)

        learner.maybe_save()  # count = 1
        learner.maybe_save()  # count = 2
        assert len(save_called) == 0

        learner.maybe_save()  # count = 3 -> triggers save
        assert len(save_called) == 1
        assert learner._request_count == 0  # reset after save

        whitelist.save = original_save

    def test_force_save(self, learner, whitelist):
        """Test force save."""
        save_called = []
        original_save = whitelist.save
        whitelist.save = lambda: save_called.append(True)

        learner.save()
        assert len(save_called) == 1

        whitelist.save = original_save
