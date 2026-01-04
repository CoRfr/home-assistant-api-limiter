"""Configuration management for HA API Limiter."""

import fnmatch
import re
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
        self._endpoint_patterns: list[re.Pattern] = []

    def load(self) -> None:
        """Load whitelist from config file."""
        if self.config_path and self.config_path.exists():
            with open(self.config_path) as f:
                data = yaml.safe_load(f) or {}
            self.endpoints = data.get("endpoints", [])
            self.entities = data.get("entities", [])
            self._compile_endpoint_patterns()

    def save(self) -> None:
        """Save current whitelist to config file."""
        if not self.config_path:
            return

        data = {
            "endpoints": sorted(set(self.endpoints)),
            "entities": sorted(set(self.entities)),
        }

        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def _compile_endpoint_patterns(self) -> None:
        """Compile endpoint patterns to regex for matching."""
        self._endpoint_patterns = []
        for endpoint in self.endpoints:
            # Convert {param} style placeholders to regex
            pattern = re.sub(r"\{[^}]+\}", r"[^/]+", re.escape(endpoint))
            pattern = pattern.replace(r"\*", ".*")
            self._endpoint_patterns.append(re.compile(f"^{pattern}$"))

    def add_endpoint(self, endpoint: str) -> bool:
        """Add an endpoint to the whitelist. Returns True if newly added."""
        if endpoint not in self.endpoints:
            self.endpoints.append(endpoint)
            self._compile_endpoint_patterns()
            return True
        return False

    def add_entity(self, entity_id: str) -> bool:
        """Add an entity to the whitelist. Returns True if newly added."""
        if entity_id not in self.entities:
            self.entities.append(entity_id)
            return True
        return False

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

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "endpoints": self.endpoints,
            "entities": self.entities,
        }


# Global settings instance
settings = Settings()
