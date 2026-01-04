"""Configuration management for HA API Limiter."""

import fnmatch
import re
import shutil
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedSeq

# Base config.yaml location (project root)
BASE_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


class Mode(str, Enum):
    """Operating mode for the proxy."""

    LEARN = "learn"
    LIMIT = "limit"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    ha_url: str = Field(default="http://localhost:8123", description="Home Assistant URL")
    mode: Mode = Field(default=Mode.LIMIT, description="Operating mode: learn or limit")
    config_path: Path = Field(default=Path("./config.yaml"), description="Path to whitelist config")
    port: int = Field(default=8080, description="Proxy listen port")
    host: str = Field(default="0.0.0.0", description="Proxy listen host")


class WhitelistConfig:
    """Manages the whitelist configuration for endpoints and entities."""

    def __init__(self, config_path: Path | None = None):
        self.config_path = config_path
        self.endpoints: list[str] = []
        self.entities: list[str] = []
        self.devices: list[str] = []
        self.areas: list[str] = []
        self._endpoint_patterns: list[re.Pattern] = []
        # Advanced WebSocket security overrides
        self.allowed_ws_types: list[str] = []
        self.allowed_event_types: list[str] = []
        self.allowed_services: list[str] = []

    def load(self) -> None:
        """Load whitelist from config file."""
        if self.config_path and self.config_path.exists():
            with open(self.config_path) as f:
                data = yaml.safe_load(f) or {}
            # Ensure we always have lists, even if YAML has null values
            self.endpoints = data.get("endpoints") or []
            self.entities = data.get("entities") or []
            self.devices = data.get("devices") or []
            self.areas = data.get("areas") or []
            # Advanced WebSocket security overrides
            self.allowed_ws_types = data.get("allowed_ws_types") or []
            self.allowed_event_types = data.get("allowed_event_types") or []
            self.allowed_services = data.get("allowed_services") or []
            self._compile_endpoint_patterns()

    def save(self) -> None:
        """Save current whitelist to config file, preserving comments."""
        if not self.config_path:
            return

        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        ruamel = YAML()
        ruamel.preserve_quotes = True
        ruamel.indent(mapping=2, sequence=2, offset=2)

        # If config doesn't exist, copy base config.yaml as template
        if not self.config_path.exists() and BASE_CONFIG_PATH.exists():
            shutil.copy(BASE_CONFIG_PATH, self.config_path)

        # Load existing file to preserve comments and structure
        if self.config_path.exists():
            with open(self.config_path) as f:
                data = ruamel.load(f)
            if data is None:
                data = {}
        else:
            data = {}

        # Helper to append items to a list, creating if needed
        def append_items(key: str, items: list[str]) -> None:
            existing = list(data.get(key) or [])
            new_items = [item for item in items if item not in existing]
            if not new_items:
                return

            if key in data:
                if isinstance(data[key], CommentedSeq):
                    # Append to existing CommentedSeq to preserve structure
                    for item in sorted(new_items):
                        data[key].append(item)
                else:
                    # Convert empty list to CommentedSeq and append in place
                    seq = CommentedSeq(existing + sorted(new_items))
                    data[key] = seq
            else:
                # Key doesn't exist, create new list
                data[key] = existing + sorted(new_items)

        append_items("endpoints", self.endpoints)
        append_items("entities", self.entities)
        append_items("devices", self.devices)
        append_items("areas", self.areas)

        with open(self.config_path, "w") as f:
            ruamel.dump(data, f)

    def _compile_endpoint_patterns(self) -> None:
        """Compile endpoint patterns to regex for matching."""
        self._endpoint_patterns = []
        for endpoint in self.endpoints:
            # First replace {param} placeholders with a marker
            # Then escape, then replace marker with regex
            marker = "__PARAM__"
            temp = re.sub(r"\{[^}]+\}", marker, endpoint)
            pattern = re.escape(temp)
            pattern = pattern.replace(marker, "[^/]+")
            pattern = pattern.replace(r"\*", ".*")
            self._endpoint_patterns.append(re.compile(f"^{pattern}$"))

    def add_endpoint(self, endpoint: str) -> bool:
        """Add an endpoint to the whitelist. Returns True if newly added."""
        # Skip if already in list
        if endpoint in self.endpoints:
            return False
        # Skip if already covered by an existing pattern (e.g., wildcard)
        if self.is_endpoint_allowed(endpoint):
            return False
        self.endpoints.append(endpoint)
        self._compile_endpoint_patterns()
        return True

    def add_entity(self, entity_id: str) -> bool:
        """Add an entity to the whitelist. Returns True if newly added."""
        # Skip if already in list or matches existing pattern
        if entity_id in self.entities or self.is_entity_allowed(entity_id):
            return False
        self.entities.append(entity_id)
        return True

    def add_device(self, device_id: str) -> bool:
        """Add a device to the whitelist. Returns True if newly added."""
        # Skip if already in list or matches existing pattern
        if device_id in self.devices or self.is_device_allowed(device_id):
            return False
        self.devices.append(device_id)
        return True

    def add_area(self, area_id: str) -> bool:
        """Add an area to the whitelist. Returns True if newly added."""
        # Skip if already in list or matches existing pattern
        if area_id in self.areas or self.is_area_allowed(area_id):
            return False
        self.areas.append(area_id)
        return True

    def is_endpoint_allowed(self, path: str) -> bool:
        """Check if an endpoint path is allowed."""
        for pattern in self._endpoint_patterns:
            if pattern.match(path):
                return True
        return False

    def is_entity_allowed(self, entity_id: str) -> bool:
        """Check if an entity ID is allowed (supports wildcards)."""
        for pattern in self.entities:
            if fnmatch.fnmatch(entity_id, pattern):
                return True
        return False

    def is_device_allowed(self, device_id: str) -> bool:
        """Check if a device ID is allowed (supports wildcards)."""
        for pattern in self.devices:
            if fnmatch.fnmatch(device_id, pattern):
                return True
        return False

    def is_area_allowed(self, area_id: str) -> bool:
        """Check if an area ID is allowed (supports wildcards)."""
        for pattern in self.areas:
            if fnmatch.fnmatch(area_id, pattern):
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "endpoints": self.endpoints,
            "entities": self.entities,
            "devices": self.devices,
            "areas": self.areas,
        }


# Global settings instance
settings = Settings()
