"""
polyglot/python/config_parser.py

A headless, config-as-code DAST runner that crawls an authenticated 
web/mobile-API surface and fires a curated active-scan ruleset, 
emitting deduplicated SARIF.

This module provides the configuration parser for dastlite.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Try to import pydantic for validation; fall back gracefully if missing
try:
    from pydantic import BaseModel, Field, validator, ValidationError
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False


@dataclass
class AuthConfig:
    """Authentication configuration."""
    type: str = "basic"  # basic, bearer, oauth2, ntlm
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    scope: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {}
        if self.type:
            result["type"] = self.type
        if self.username:
            result["username"] = self.username
        if self.password:
            result["password"] = self.password
        if self.token:
            result["token"] = self.token
        if self.scope:
            result["scope"] = self.scope
        return result


@dataclass
class TargetConfig:
    """Target URL configuration."""
    base_url: str
    paths: List[str] = field(default_factory=lambda: ["/"])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "paths": self.paths,
        }


@dataclass
class RulesetConfig:
    """Active-scan ruleset configuration."""
    enabled: bool = True
    categories: List[str] = field(default_factory=lambda: [
        "xss", 
        "csrf", 
        "sql-injection", 
        "broken-authentication"
    ])
    severity_threshold: str = "medium"  # low, medium, high
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "categories": self.categories,
            "severity_threshold": self.severity_threshold,
        }


@dataclass
class OutputConfig:
    """Output format configuration."""
    formats: List[str] = field(default_factory=lambda: ["sarif"])
    output_dir: str = "."
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "formats": self.formats,
            "output_dir": self.output_dir,
        }


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_second: float = 10.0
    burst_size: int = 50
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "requests_per_second": self.requests_per_second,
            "burst_size": self.burst_size,
        }


@dataclass
class Config:
    """Complete DASTLite configuration."""
    targets: TargetConfig = field(default_factory=TargetConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    ruleset: RulesetConfig = field(default_factory=RulesetConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "targets": self.targets.to_dict(),
            "auth": self.auth.to_dict(),
            "ruleset": self.ruleset.to_dict(),
            "output": self.output.to_dict(),
            "rate_limit": self.rate_limit.to_dict(),
        }


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    """Load and parse a YAML file."""
    try:
        import yaml
    except ImportError:
        # Fallback to json if pyyaml not available
        with open(path) as f:
            return json.load(f)
    
    with open(path) as f:
        data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}


def _load_json_file(path: Path) -> Dict[str, Any]:
    """Load and parse a JSON file."""
    with open(path) as f:
        return json.load(f)


def _expand_env_vars(value: str) -> str:
    """Expand environment variables in a string value."""
    if not isinstance(value, str):
        return value
    
    result = os.path.expandvars(value)
    
    # Handle ${VAR} style for better compatibility
    import re
    def replace_var(match):
        var_name = match.group(1)
        env_val = os.environ.get(var_name, "")
        if not env_val:
            # Try to load from config file fallback
            return match.group(0)
        return env_val
    
    pattern = r'\$\{([^}]+)\}'
    result = re.sub(pattern, replace_var, result)
    
    return result


def _merge_configs(base: Dict[str, Any], override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Recursively merge override into base config."""
    if not override:
        return base
    
    merged = dict(base)
    for key in override:
        if isinstance(merged.get(key), dict) and isinstance(override[key], dict):
            merged[key] = _merge_configs(merged[key], override[key])
        else:
            merged[key] = override[key]
    
    return merged


def parse_config_file(
    path: Union[str, Path],
    env_override: Optional[Dict[str, Any]] = None
) -> Config:
    """
    Parse a configuration file and return a validated Config object.
    
    Args:
        path: Path to the config file (YAML or JSON).
        env_override: Optional dictionary of environment variable overrides.
    
    Returns:
        A fully parsed and validated Config object.
    
    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the config format is invalid.
    """
    path = Path(path)
    
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {path}"
        )
    
    # Load raw data
    try:
        with open(path) as f:
            raw_data = json.load(f)
    except json.JSONDecodeError:
        raw_data = _load_yaml_file(path)
    
    if not isinstance(raw_data, dict):
        raise ValueError(
            f"Config file must contain a JSON or YAML object, got {type(raw_data).__name__}"
        )
    
    # Expand environment variables in all string values
    def expand_strings(obj: Any) -> Any:
        if isinstance(obj, str):
            return _expand_env_vars(obj)
        elif isinstance(obj, dict):
            return {k: expand_strings(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [expand_strings(item) for item in obj]
        else:
            return obj
    
    expanded_data = expand_strings(raw_data)
    
    # Merge environment overrides if provided
    merged_data = _merge_configs(expanded_data, env_override)
    
    # Parse into Config object
    try:
        config = Config(**merged_data)
    except TypeError as e:
        raise ValueError(f"Invalid config format: {e}") from e
    
    return config


def validate_config(config: Config) -> List[str]:
    """
    Perform additional validation checks on a parsed config.
    
    Returns a list of warning messages (empty if all checks pass).
    """
    warnings = []
    
    # Check for common issues
    if not config.targets.base_url:
        warnings.append("Warning: No base URL specified in targets")
    
    if not config.auth.type:
        warnings.append("Warning: Authentication type not specified; will use basic auth")
    
    if config.rate_limit.requests_per_second > 100.0:
        warnings.append(
            f"Warning: High request rate ({config.rate_limit.requests_per_second}/s) "
            "may cause target server issues"
        )
    
    # Check output directory exists or is writable
    try:
        Path(config.output.output_dir).mkdir(parents=True, exist_ok=True)
    except OSError as e:
        warnings.append(f"Warning: Output directory may not be writable: {e}")
    
    return warnings


def load_and_validate_config(
    path: Union[str, Path],
    env_override: Optional[Dict[str, Any]] = None
) -> Config:
    """
    Convenience function to load, parse, and validate a config file.
    
    Returns the parsed Config along with any warning messages.
    """
    try:
        config = parse_config_file(path, env_override)
        warnings = validate_config(config)
        
        if warnings:
            for w in warnings:
                print(f"  {w}")
        
        return config
    
    except (FileNotFoundError, ValueError) as e:
        print(f"Error loading config: {e}")
        raise


def create_default_config() -> Config:
    """Create a default configuration with sensible defaults."""
    warnings = validate_config(Config())
    
    if warnings:
        for w in warnings:
            print(f"  Default warning: {w}")
    
    return Config()


# ============================================================================
# Demo / Entry Point
# ============================================================================

if __name__ == "__main__":
    import sys
    
    # Example 1: Load from file (default demo config)
    print("=" * 60)
    print("Example 1: Loading default configuration")
    print("=" * 60)
    
    # Create a temporary config for demonstration
    temp_config = Path("/tmp/dastlite-demo-config.yaml")
    
    # Write a sample config file
    sample_yaml = """
# DASTLite Demo Configuration
targets:
  base_url: "https://example.com"
  paths:
    - "/"
    - "/api/v1"

auth:
  type: "bearer"
  token: "${DASTLITE_TOKEN:-demo-token-12345}"

ruleset:
  enabled: true
  categories:
    - xss
    - csrf
  severity_threshold: "high"

output:
  formats: ["sarif", "json"]
  output_dir: "./results"

rate_limit:
  requests_per_second: 25.0
  burst_size: 100
"""
    
    with open(temp_config, 'w') as f:
        f.write(sample_yaml)
    
    # Parse and display the config
    print(f"\nLoading from: {temp_config}")
    config = parse_config_file(temp_config)
    
    print("\nParsed Configuration:")
    print("-" * 40)
    print(json.dumps(config.to_dict(), indent=2))
    
    # Validate and show warnings
    print("\nValidation Warnings:")
    print("-" * 40)
    warnings = validate_config(config)
    if not warnings:
        print("  None (all checks passed)")
    else:
        for w in warnings:
            print(f"  - {w}")
    
    # Example 2: Load from command line argument or default
    print("\n" + "=" * 60)
    print("Example 2: Loading with environment override")
    print("=" * 60)
    
    env_override = {
        "targets": {"base_url": "https://api.example.com"},
        "auth": {"type": "basic", "username": "admin"}
    }
    
    config_overridden = parse_config_file(temp_config, env_override=env_override)
    print(f"\nOverridden base_url: {config_overridden.targets.base_url}")
    print(f"Overridden auth type: {config_overridden.auth.type}")
    
    # Example 3: Create default config
    print("\n" + "=" * 60)
    print("Example 3: Creating default configuration")
    print("=" * 60)
    
    default_config = create_default_config()
    print(f"\nDefault output directory: {default_config.output.output_dir}")
    print(f"Default ruleset enabled: {default_config.ruleset.enabled}")
    
    # Cleanup temp file
    if temp_config.exists():
        temp_config.unlink()
    
    print("\nDemo complete!")