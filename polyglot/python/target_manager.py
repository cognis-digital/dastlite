"""
polyglot/python/target_manager.py

Target Manager for dastlite — a headless, config-as-code DAST runner.

This module provides:
  • Target configuration parsing from YAML/JSON/CLI/env
  • Multi-source auth (basic, OAuth2, API keys, cookies)
  • Configuration inheritance and merging
  • Validation of URLs and credentials before scanning starts
"""

from __future__ import annotations

import base64
import dataclasses
import fnmatch
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import uuid
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import lru_cache
from pathlib import Path
from typing import (
    Any, Callable, ClassVar, Iterator, Optional, TextIO, TypeVar, Union
)

# --- Constants & Config Paths -------------------------------------------------

DEFAULT_CONFIG_PATH = "~/.dastlite/config.yaml"
ENV_PREFIX = "DASTLITE_"
CONFIG_ENV_VAR = f"{ENV_PREFIX}CONFIG_FILE"
TARGETS_ENV_VAR = f"{ENV_PREFIX}TARGETS"


# --- Enums --------------------------------------------------------------------

class AuthType(Enum):
    BASIC = auto()
    OAUTH2 = auto()
    API_KEY = auto()
    BEARER_TOKEN = auto()
    COOKIE = auto()
    CUSTOM_HEADER = auto()
    SESSION = auto()
    NONE = auto()


# --- Data Classes: Core Configuration -----------------------------------------

@dataclass(frozen=True)
class AuthConfig:
    """Authentication configuration for a target."""
    
    type: AuthType = AuthType.BASIC
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_scope: str = "read"
    oauth_redirect_uri: str = ""
    oauth_token_url: str = ""
    bearer_token: Optional[str] = None
    cookie_name: Optional[str] = None
    custom_headers: dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.type == AuthType.BASIC and not (self.username or self.password):
            object.__setattr__(self, 'type', AuthType.NONE)


@dataclass(frozen=True)
class ScheduleConfig:
    """Scheduling configuration for a target."""
    
    rate_limit: int = 100
    retry_count: int = 3
    retry_delay: float = 5.0
    timeout_seconds: int = 60
    max_concurrent: int = 4


@dataclass(frozen=True)
class OutputConfig:
    """Output configuration for a target."""
    
    format: str = "sarif"
    output_file: Optional[str] = None
    deduplicate: bool = True
    include_raw_response: bool = False
    
    def __post_init__(self):
        if self.format not in ("sarif", "json", "html", "text"):
            object.__setattr__(self, 'format', 'sarif')


@dataclass(frozen=True)
class TargetConfig:
    """Complete configuration for a single DAST target."""
    
    name: str = ""
    base_url: str = ""
    paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    auth: AuthConfig = field(default_factory=AuthConfig)
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    
    # Computed properties
    effective_base_url: str = ""
    effective_paths: list[str] = field(default_factory=list)
    effective_exclude_paths: list[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.base_url:
            object.__setattr__(self, 'base_url', "http://localhost")
        
        # Normalize paths
        self.effective_base_url = urllib.parse.urljoin(
            "https://" + self.base_url.lstrip("/")
        )
        
        # Parse and normalize path patterns
        for p in self.paths:
            if not p.startswith("/"):
                object.__setattr__(self, 'paths', 
                    [f"/{p}" if not p.startswith("/") else p])
        
        for p in self.exclude_paths:
            if not p.startswith("/"):
                object.__setattr__(self, 'exclude_paths',
                    [f"/{p}" if not p.startswith("/") else p])


# --- Schema Validation ---------------------------------------------------------

@dataclass(frozen=True)
class ValidationError(Exception):
    """Raised when configuration validation fails."""
    
    message: str = ""
    target_name: Optional[str] = None
    
    def __str__(self) -> str:
        if self.target_name:
            return f"[{self.target_name}] {self.message}"
        return self.message


def validate_url(url: str, name: str = "URL") -> bool:
    """Basic URL validation."""
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc or not (parsed.scheme in ("http", "https")):
            raise ValidationError(
                f"Invalid {name}: must be http(s)://...",
                name
            )
        return True
    except Exception as e:
        raise ValidationError(f"{name} parse error: {e}", name)


def validate_auth(auth: AuthConfig, target_name: str = "Target") -> None:
    """Validate authentication configuration."""
    if auth.type == AuthType.BASIC and not (auth.username or auth.password):
        raise ValidationError(
            f"{target_name} basic auth missing credentials",
            target_name
        )
    
    if auth.type == AuthType.OAUTH2:
        required = [auth.oauth_token_url]
        if auth.oauth_client_id and auth.oauth_client_secret:
            required.append(auth.oauth_redirect_uri)
        
        for field in required:
            if not field:
                raise ValidationError(
                    f"{target_name} OAuth2 missing {field}",
                    target_name
                )


def validate_config(target: TargetConfig, name: str = "Target") -> None:
    """Validate a complete target configuration."""
    try:
        validate_url(target.base_url, name)
        validate_auth(target.auth, name)
        
        # Check for path conflicts
        all_paths = set(target.effective_paths) | set(target.effective_exclude_paths)
        duplicates = [p for p in all_paths if all_paths.count(p) > 1]
        if duplicates:
            raise ValidationError(
                f"{name} has duplicate paths: {duplicates}",
                name
            )
    except ValidationError as e:
        raise


# --- Target Manager Implementation --------------------------------------------

class TargetManagerError(Exception):
    """Base exception for target manager errors."""
    pass


@dataclass(frozen=True)
class LoadedTarget:
    """A target that has been loaded from configuration."""
    
    config: TargetConfig
    load_time: float = field(default_factory=time.time)
    source: str = "unknown"
    index: int = -1
    
    def __hash__(self):
        return hash(self.config.effective_base_url)


class ConfigSource(Enum):
    """Configuration sources in priority order."""
    
    CLI = auto()
    ENV_VAR = auto()
    DEFAULT_FILE = auto()
    TARGET_FILE = auto()
    INLINE = auto()


@dataclass(frozen=True)
class LoadedConfig:
    """Complete loaded configuration including all targets."""
    
    sources: list[ConfigSource] = field(default_factory=list)
    targets: dict[str, LoadedTarget] = field(default_factory=dict)
    global_config: Optional[Any] = None
    
    def __iter__(self) -> Iterator[LoadedTarget]:
        return iter(self.targets.values())


class TargetManager:
    """
    Manages the lifecycle of DAST targets.
    
    Thread-safe and supports concurrent loading from multiple sources.
    """
    
    _instance: Optional["TargetManager"] = None
    _lock: threading.RLock = threading.RLock()
    
    def __new__(cls, *args, **kwargs) -> "TargetManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.__init__(*args, **kwargs)
        return cls._instance
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path or DEFAULT_CONFIG_PATH).expanduser()
        self.loaded_config: LoadedConfig = LoadedConfig()
        self.load_time: float = time.time()
    
    @classmethod
    def reset(cls) -> "TargetManager":
        """Reset singleton instance for testing."""
        with cls._lock:
            cls._instance = None
            return cls()
    
    @property
    def targets(self) -> dict[str, LoadedTarget]:
        """Get all loaded targets by base URL."""
        return self.loaded_config.targets
    
    @property
    def target_count(self) -> int:
        """Total number of loaded targets."""
        return len(self.loaded_config.targets)
    
    @contextmanager
    def _acquire_lock(self):
        with self._lock:
            yield
    
    def load_from_cli(
        self, 
        urls: Sequence[str], 
        sources: list[ConfigSource] = (ConfigSource.CLI,)
    ) -> None:
        """Load targets from command-line arguments."""
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                
                target_config = TargetConfig(
                    name=f"cli_{uuid.uuid4().hex[:8]}",
                    base_url=base_url,
                    paths=["/"],
                    auth=AuthConfig(type=AuthType.NONE)
                )
                
                with self._acquire_lock():
                    if base_url not in self.loaded_config.targets:
                        self.loaded_config.targets[base_url] = LoadedTarget(
                            config=target_config,
                            source="cli"
                        )
                    
            except Exception as e:
                print(f"CLI target error: {e}", file=sys.stderr)
    
    def load_from_env(self) -> None:
        """Load targets from environment variables."""
        env_targets = os.environ.get(TARGETS_ENV_VAR, "")
        
        if not env_targets:
            return
        
        # Parse JSON array from env var
        try:
            targets_list = json.loads(env_targets)
            
            for item in targets_list:
                self._parse_env_target(item)
                
        except (json.JSONDecodeError, TypeError):
            pass
    
    def _parse_env_target(self, raw: Any) -> None:
        """Parse a single target from environment variable."""
        if isinstance(raw, dict):
            # Convert to TargetConfig
            config = self._dict_to_config(raw)
            
            with self._acquire_lock():
                base_url = urllib.parse.urljoin(
                    "https://" + config.base_url.lstrip("/")
                )
                
                if base_url not in self.loaded_config.targets:
                    self.loaded_config.targets[base_url] = LoadedTarget(
                        config=config,
                        source="env"
                    )
                    
        elif isinstance(raw, str):
            # Simple URL string
            try:
                parsed = urllib.parse.urlparse(raw)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                
                with self._acquire_lock():
                    if base_url not in self.loaded_config.targets:
                        self.loaded_config.targets[base_url] = LoadedTarget(
                            config=TargetConfig(
                                name=f"env_{uuid.uuid4().hex[:8]}",
                                base_url=base_url,
                                paths=["/"],
                                auth=AuthConfig(type=AuthType.NONE)
                            ),
                            source="env"
                        )
                        
            except Exception:
                pass
    
    def _dict_to_config(self, data: Mapping[str, Any]) -> TargetConfig:
        """Convert a dictionary to a TargetConfig."""
        
        # Helper to recursively convert nested dicts
        def convert_value(val):
            if isinstance(val, dict):
                return {k: convert_value(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [convert_value(item) for item in val]
            else:
                return val
        
        converted = convert_value(data)
        
        # Extract auth config
        auth_data = converted.get("auth", {})
        if not auth_data:
            auth_data = {}
        
        auth_type_str = auth_data.get("type", "basic")
        try:
            auth_type = AuthType(auth_type_str.upper())
        except ValueError:
            auth_type = AuthType.BASIC
        
        # Build auth config
        auth_config = AuthConfig(
            type=auth_type,
            username=auth_data.get("username"),
            password=auth_data.get("password"),
            api_key=auth_data.get("api_key"),
            oauth_client_id=auth_data.get("client_id"),
            oauth_client_secret=auth_data.get("client_secret"),
            oauth_scope=auth_data.get("scope", "read"),
            oauth_redirect_uri=auth_data.get("redirect_uri", ""),
            oauth_token_url=auth_data.get("token_url", ""),
            bearer_token=auth_data.get("bearer_token"),
            cookie_name=auth_data.get("cookie_name"),
            custom_headers={k: v for k, v in auth_data.items() 
                          if k not in ("type", "username", "password")}
        )
        
        # Build schedule config
        schedule_config = ScheduleConfig(
            rate_limit=int(auth_data.get("rate_limit", 100)),
            retry_count=int(auth_data.get("retry_count", 3)),
            retry_delay=float(auth_data.get("retry_delay", 5.0)),
            timeout_seconds=int(auth_data.get("timeout_seconds", 60))
        )
        
        # Build output config
        output_config = OutputConfig(
            format=auth_data.get("format", "sarif"),
            output_file=auth_data.get("output_file"),
            deduplicate=bool(auth_data.get("deduplicate", True)),
            include_raw_response=bool(auth_data.get("raw_response", False))
        )
        
        # Build paths
        paths = auth_data.get("paths", [])
        exclude_paths = auth_data.get("exclude_paths", [])
        
        return TargetConfig(
            name=auth_data.get("name", ""),
            base_url=str(auth_data.get("base_url", "http://localhost")),
            paths=paths,
            exclude_paths=exclude_paths,
            auth=auth_config,
            schedule=schedule_config,
            output=output_config
        )
    
    def load_from_file(
        self, 
        path: Path, 
        source: ConfigSource = ConfigSource.DEFAULT_FILE
    ) -> None:
        """Load configuration from a YAML/JSON file."""
        
        if not path.exists():
            return
        
        try:
            content = path.read_text()
            
            # Auto-detect format
            if content.strip().startswith("{"):
                data = json.loads(content)
            else:
                import yaml
                data = yaml.safe_load(content) or {}
            
            self._parse_file_data(data, source=source)
            
        except Exception as e:
            print(f"Config file error ({path}): {e}", file=sys.stderr)
    
    def _parse_file_data(self, data: Any, source: ConfigSource = ConfigSource.INLINE) -> None:
        """Parse configuration data into targets."""
        
        if isinstance(data, dict):
            # Top-level might be a single target or a list of targets
            if "targets" in data:
                for item in data["targets"]:
                    self._parse_env_target(item)
            else:
                # Single target config
                self._parse_env_target(data)
        
        elif isinstance(data, list):
            for item in data:
                self._parse_env_target(item)


# --- Utility Functions ---------------------------------------------------------

def expand_env_vars(value: str) -> str:
    """Expand environment variables in a string."""
    
    def replacer(match: re.Match[str]) -> str:
        var_name = match.group(1)
        env_value = os.environ.get(var_name, "")