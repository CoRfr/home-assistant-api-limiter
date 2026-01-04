"""Tests for configuration management."""

import tempfile
from pathlib import Path

from ha_api_limiter.config import WhitelistConfig


class TestWhitelistConfig:
    """Tests for WhitelistConfig."""

    def test_init_defaults(self):
        """Test default initialization."""
        wl = WhitelistConfig()
        assert wl.endpoints == []
        assert wl.entities == []
        assert wl.devices == []
        assert wl.areas == []
        assert wl.allowed_ws_types == []
        assert wl.allowed_event_types == []
        assert wl.allowed_services == []

    def test_init_with_path(self):
        """Test initialization with config path."""
        wl = WhitelistConfig(Path("/tmp/test.yaml"))
        assert wl.config_path == Path("/tmp/test.yaml")

    def test_load_nonexistent_file(self):
        """Test loading from non-existent file."""
        wl = WhitelistConfig(Path("/nonexistent/config.yaml"))
        wl.load()
        assert wl.endpoints == []

    def test_load_and_save(self):
        """Test loading and saving config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text(
                """
endpoints:
  - /api/states
entities:
  - light.test
devices:
  - device123
areas:
  - living_room
allowed_ws_types:
  - render_template
allowed_event_types:
  - custom_event
allowed_services:
  - automation.trigger
"""
            )
            wl = WhitelistConfig(config_path)
            wl.load()

            assert "/api/states" in wl.endpoints
            assert "light.test" in wl.entities
            assert "device123" in wl.devices
            assert "living_room" in wl.areas
            assert "render_template" in wl.allowed_ws_types
            assert "custom_event" in wl.allowed_event_types
            assert "automation.trigger" in wl.allowed_services

    def test_add_endpoint(self):
        """Test adding endpoints."""
        wl = WhitelistConfig()
        wl._compile_endpoint_patterns()

        # Add new endpoint
        assert wl.add_endpoint("/api/states") is True
        assert "/api/states" in wl.endpoints

        # Add duplicate - should return False
        assert wl.add_endpoint("/api/states") is False

    def test_add_endpoint_covered_by_pattern(self):
        """Test that endpoint covered by existing pattern is not added."""
        wl = WhitelistConfig()
        wl.endpoints = ["/api/*"]
        wl._compile_endpoint_patterns()

        # /api/states is covered by /api/*
        assert wl.add_endpoint("/api/states") is False

    def test_add_entity(self):
        """Test adding entities."""
        wl = WhitelistConfig()

        assert wl.add_entity("light.living_room") is True
        assert "light.living_room" in wl.entities

        # Duplicate
        assert wl.add_entity("light.living_room") is False

    def test_add_entity_covered_by_wildcard(self):
        """Test that entity covered by wildcard is not added."""
        wl = WhitelistConfig()
        wl.entities = ["light.*"]

        # light.bedroom is covered by light.*
        assert wl.add_entity("light.bedroom") is False

    def test_add_device(self):
        """Test adding devices."""
        wl = WhitelistConfig()

        assert wl.add_device("device123") is True
        assert "device123" in wl.devices

        # Duplicate
        assert wl.add_device("device123") is False

    def test_add_area(self):
        """Test adding areas."""
        wl = WhitelistConfig()

        assert wl.add_area("living_room") is True
        assert "living_room" in wl.areas

        # Duplicate
        assert wl.add_area("living_room") is False

    def test_is_endpoint_allowed(self):
        """Test endpoint matching."""
        wl = WhitelistConfig()
        wl.endpoints = ["/api/states", "/api/services/{domain}/{service}"]
        wl._compile_endpoint_patterns()

        assert wl.is_endpoint_allowed("/api/states") is True
        assert wl.is_endpoint_allowed("/api/services/light/turn_on") is True
        assert wl.is_endpoint_allowed("/api/config") is False

    def test_is_entity_allowed_exact(self):
        """Test exact entity matching."""
        wl = WhitelistConfig()
        wl.entities = ["light.living_room", "sensor.temperature"]

        assert wl.is_entity_allowed("light.living_room") is True
        assert wl.is_entity_allowed("sensor.temperature") is True
        assert wl.is_entity_allowed("light.bedroom") is False

    def test_is_entity_allowed_wildcard(self):
        """Test wildcard entity matching."""
        wl = WhitelistConfig()
        wl.entities = ["light.*", "sensor.weather_*"]

        assert wl.is_entity_allowed("light.living_room") is True
        assert wl.is_entity_allowed("light.bedroom") is True
        assert wl.is_entity_allowed("sensor.weather_temperature") is True
        assert wl.is_entity_allowed("sensor.humidity") is False

    def test_is_device_allowed(self):
        """Test device matching."""
        wl = WhitelistConfig()
        wl.devices = ["device123", "device_*"]

        assert wl.is_device_allowed("device123") is True
        assert wl.is_device_allowed("device_abc") is True
        assert wl.is_device_allowed("other") is False

    def test_is_area_allowed(self):
        """Test area matching."""
        wl = WhitelistConfig()
        wl.areas = ["living_room", "bedroom_*"]

        assert wl.is_area_allowed("living_room") is True
        assert wl.is_area_allowed("bedroom_1") is True
        assert wl.is_area_allowed("kitchen") is False

    def test_to_dict(self):
        """Test converting config to dict."""
        wl = WhitelistConfig()
        wl.endpoints = ["/api/states"]
        wl.entities = ["light.test"]
        wl.devices = ["device123"]
        wl.areas = ["living_room"]

        d = wl.to_dict()
        assert d["endpoints"] == ["/api/states"]
        assert d["entities"] == ["light.test"]
        assert d["devices"] == ["device123"]
        assert d["areas"] == ["living_room"]

    def test_save_creates_directory(self):
        """Test that save creates parent directory if needed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "subdir" / "config.yaml"
            wl = WhitelistConfig(config_path)
            wl.endpoints = ["/api/test"]
            wl.save()

            assert config_path.exists()

    def test_save_appends_to_existing(self):
        """Test that save appends to existing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text(
                """
endpoints:
  - /api/states
entities: []
devices: []
areas: []
"""
            )
            wl = WhitelistConfig(config_path)
            wl.load()

            # Add new endpoint
            wl.add_endpoint("/api/config")
            wl.save()

            # Reload and verify
            wl2 = WhitelistConfig(config_path)
            wl2.load()
            assert "/api/states" in wl2.endpoints
            assert "/api/config" in wl2.endpoints
