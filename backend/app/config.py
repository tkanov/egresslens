"""Configuration for EgressLens backend."""
import os
import yaml
from pathlib import Path
from pydantic import BaseModel
from typing import List


class FlagThresholds(BaseModel):
    """Configuration for security flags calculation."""
    high_dest_threshold: int = 50
    """Threshold for number of unique destination IP:port pairs to trigger 'High unique destinations' flag."""
    
    failure_threshold: float = 0.10
    """Threshold for failure rate (0.0-1.0) to trigger 'Elevated failure rate' flag."""
    
    usual_ports: List[int] = [80, 443, 53, 22]
    """List of ports considered 'usual'. Connections to other ports trigger 'Unusual ports' flag."""


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
    if os.getenv("FLAG_HIGH_DEST_THRESHOLD"):
        config_dict["flags"]["high_dest_threshold"] = int(os.getenv("FLAG_HIGH_DEST_THRESHOLD"))
    
    if os.getenv("FLAG_FAILURE_THRESHOLD"):
        config_dict["flags"]["failure_threshold"] = float(os.getenv("FLAG_FAILURE_THRESHOLD"))
    
    if os.getenv("FLAG_USUAL_PORTS"):
        # Parse comma-separated port list
        ports_str = os.getenv("FLAG_USUAL_PORTS")
        config_dict["flags"]["usual_ports"] = [int(p.strip()) for p in ports_str.split(",")]
    
    return Settings(**config_dict)


# Global settings instance
settings = load_config()
