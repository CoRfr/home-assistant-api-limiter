"""Tests for request limiting functionality."""

import pytest

from ha_api_limiter.config import WhitelistConfig
from ha_api_limiter.limiter import Limiter


@pytest.fixture
def whitelist():
    """Create a whitelist for testing."""
    wl = WhitelistConfig()
    wl.endpoints = [
        "/api/states",
        "/api/states/{entity_id}",
        "/api/services/{domain}/{service}",
        "/api/history/period/*",
        "/static/*",
    ]
    wl.entities = [
        "light.living_room",
        "light.kitchen",
        "sensor.temperature",
        "sensor.weather_*",
    ]
    wl._compile_endpoint_patterns()
    return wl


@pytest.fixture
def limiter(whitelist):
    """Create a limiter for testing."""
    return Limiter(whitelist)


class TestEndpointAllowance:
    """Tests for endpoint access checking."""

    def test_exact_endpoint_allowed(self, limiter):
        """Test that exact endpoint matches are allowed."""
        result = limiter.check_request("/api/states", "GET", "")
        assert result.allowed is True

    def test_parameterized_endpoint_allowed(self, limiter):
        """Test that parameterized endpoints are allowed."""
        # Use whitelisted entity (sensor.temperature is in the fixture)
        result = limiter.check_request("/api/states/sensor.temperature", "GET", "")
        assert result.allowed is True

        result = limiter.check_request("/api/services/light/turn_on", "POST", "")
        assert result.allowed is True

    def test_wildcard_endpoint_allowed(self, limiter):
        """Test that wildcard endpoints are allowed."""
        result = limiter.check_request("/static/css/style.css", "GET", "")
        assert result.allowed is True

        result = limiter.check_request("/api/history/period/2024-01-01", "GET", "")
        assert result.allowed is True

    def test_unknown_endpoint_blocked(self, limiter):
        """Test that unknown endpoints are blocked."""
        result = limiter.check_request("/api/unknown", "GET", "")
        assert result.allowed is False
        assert "endpoint" in result.reason.lower()

    def test_health_endpoint_always_allowed(self, limiter):
        """Test that /health is always allowed."""
        result = limiter.check_request("/health", "GET", "")
        assert result.allowed is True


class TestEntityFiltering:
    """Tests for entity-based filtering in query parameters."""

    def test_allowed_entity_in_query(self, limiter):
        """Test that allowed entities in query pass."""
        result = limiter.check_request(
            "/api/history/period/2024-01-01", "GET", "filter_entity_id=light.living_room"
        )
        assert result.allowed is True

    def test_blocked_entity_in_query(self, limiter):
        """Test that non-whitelisted entities in query are blocked."""
        result = limiter.check_request(
            "/api/history/period/2024-01-01", "GET", "filter_entity_id=light.bedroom"
        )
        assert result.allowed is False
        assert "entity" in result.reason.lower()

    def test_wildcard_entity_match(self, limiter):
        """Test that wildcard patterns match."""
        result = limiter.check_request(
            "/api/history/period/2024-01-01", "GET", "filter_entity_id=sensor.weather_temperature"
        )
        assert result.allowed is True

    def test_multiple_entities_all_allowed(self, limiter):
        """Test that multiple allowed entities pass."""
        result = limiter.check_request(
            "/api/history/period/2024-01-01",
            "GET",
            "filter_entity_id=light.living_room,light.kitchen",
        )
        assert result.allowed is True

    def test_multiple_entities_one_blocked(self, limiter):
        """Test that if any entity is blocked, request is blocked."""
        result = limiter.check_request(
            "/api/history/period/2024-01-01",
            "GET",
            "filter_entity_id=light.living_room,light.bedroom",
        )
        assert result.allowed is False

    def test_entity_id_param_extracted(self, limiter):
        """Test entity_id query parameter."""
        result = limiter.check_request("/api/states", "GET", "entity_id=light.living_room")
        assert result.allowed is True

    def test_no_entity_in_query_allowed(self, limiter):
        """Test that requests without entity params are allowed."""
        result = limiter.check_request("/api/states", "GET", "")
        assert result.allowed is True
