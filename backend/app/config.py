"""Configuration for EgressLens backend."""
import os
import yaml
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List


class FlagThresholds(BaseModel):
    """Configuration for security flags calculation."""
    high_dest_threshold: int = Field(
        50,
        description="Threshold for number of unique destination IP:port pairs to "
        "trigger 'High unique destinations' flag.",
    )
    
    failure_threshold: float = Field(
        0.10,
        description="Threshold for failure rate (0.0-1.0) to trigger 'Elevated failure "
        "rate' flag.",
    )
    
    usual_ports: List[int] = Field(
        [80, 443, 53, 22],
        description="List of ports considered 'usual'. Connections to other ports "
        "trigger 'Unusual ports' flag.",
    )


class Settings(BaseModel):
    """Application settings."""
    flags: FlagThresholds = FlagThresholds()


def load_config() -> Settings:
    """Load configuration from config.yaml, environment variables, or defaults.
    
    Priority order (highest to lowest):
    1. Environment variables (FLAG_HIGH_DEST_THRESHOLD, FLAG_FAILURE_THRESHOLD, FLAG_USUAL_PORTS)
    2. config.yaml file in backend/ directory
    3. Default values in FlagThresholds
    
    Returns:
        Settings object with loaded configuration.
    """
    # Start with defaults
    config_dict = {
        "flags": {
            "high_dest_threshold": 50,
            "failure_threshold": 0.10,
            "usual_ports": [80, 443, 53, 22],
        }
    }
    
    # Load from config.yaml if it exists
    config_file = Path(__file__).parent.parent / "config.yaml"
    if config_file.exists():
        with open(config_file, "r") as f:
            yaml_config = yaml.safe_load(f) or {}
            if "flags" in yaml_config:
                config_dict["flags"].update(yaml_config["flags"])
    
    # Override with environment variables if present
    env_high_dest = os.getenv("FLAG_HIGH_DEST_THRESHOLD")
    if env_high_dest is not None and env_high_dest != "":
        try:
            config_dict["flags"]["high_dest_threshold"] = int(env_high_dest)
        except ValueError as exc:
            raise ValueError(
                f"Invalid configuration: FLAG_HIGH_DEST_THRESHOLD='{env_high_dest}' "
                "must be an integer."
            ) from exc
    
    env_failure = os.getenv("FLAG_FAILURE_THRESHOLD")
    if env_failure is not None and env_failure != "":
        try:
            failure_val = float(env_failure)
        except ValueError as exc:
            raise ValueError(
                f"Invalid configuration: FLAG_FAILURE_THRESHOLD='{env_failure}' "
                "must be a floating-point number between 0.0 and 1.0."
            ) from exc
        if not (0.0 <= failure_val <= 1.0):
            raise ValueError(
                f"Invalid configuration: FLAG_FAILURE_THRESHOLD='{env_failure}' "
                "must be between 0.0 and 1.0."
            )
        config_dict["flags"]["failure_threshold"] = failure_val
    
    ports_str = os.getenv("FLAG_USUAL_PORTS")
    if ports_str is not None and ports_str != "":
        # Parse comma-separated port list; ignore empty tokens (e.g., from trailing commas)
        ports: List[int] = []
        for raw_token in ports_str.split(","):
            token = raw_token.strip()
            if not token:
                # Skip empty entries to tolerate inputs like "80,443,"
                continue
            try:
                port = int(token)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid configuration: FLAG_USUAL_PORTS='{ports_str}' contains "
                    f"non-integer value '{token}'."
                ) from exc
            if not (1 <= port <= 65535):
                raise ValueError(
                    f"Invalid configuration: FLAG_USUAL_PORTS='{ports_str}' contains "
                    f"out-of-range port '{port}'. Ports must be between 1 and 65535."
                )
            ports.append(port)
        
        if not ports:
            raise ValueError(
                f"Invalid configuration: FLAG_USUAL_PORTS='{ports_str}' did not contain "
                "any valid port numbers."
            )
        
        config_dict["flags"]["usual_ports"] = ports
    
    return Settings(**config_dict)


# Global settings instance
settings = load_config()
