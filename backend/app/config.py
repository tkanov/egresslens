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
        description="Threshold for failure rate (0.0-1.0) to trigger Elevated failure "
        "rate flag.",
    )

    usual_ports: List[int] = Field(
        [80, 443, 53, 22],
        description="List of ports considered 'usual'. Connections to other ports "
        "trigger 'Unusual ports' flag.",
    )


class EnrichmentConfig(BaseModel):
    """Configuration for domain enrichment during report upload."""
    enabled: bool = Field(
        True,
        description="Enable backend-time domain enrichment for uploaded reports.",
    )
    reverse_dns_enabled: bool = Field(
        True,
        description="Enable bounded reverse DNS fallback for public IPs.",
    )
    reverse_dns_timeout_seconds: float = Field(
        0.5,
        gt=0,
        description="Timeout in seconds for each reverse DNS lookup.",
    )
    reverse_dns_max_ips: int = Field(
        100,
        ge=0,
        description="Maximum number of reverse DNS lookups per upload.",
    )


class Settings(BaseModel):
    """Application settings."""
    flags: FlagThresholds = FlagThresholds()
    enrichment: EnrichmentConfig = EnrichmentConfig()


def parse_bool_env(name: str, value: str) -> bool:
    """Parse a boolean environment variable."""
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(
        f"Invalid configuration: {name}='{value}' must be one of "
        "true/false, yes/no, on/off, or 1/0."
    )


def load_config() -> Settings:
    """Load configuration from config.yaml, environment variables, or defaults.

    Priority order (highest to lowest):
    1. Environment variables (FLAG_*, ENRICHMENT_*)
    2. config.yaml file in backend/ directory
    3. Default values in the settings models
    """
    config_dict = {
        "flags": {
            "high_dest_threshold": 50,
            "failure_threshold": 0.10,
            "usual_ports": [80, 443, 53, 22],
        },
        "enrichment": {
            "enabled": True,
            "reverse_dns_enabled": True,
            "reverse_dns_timeout_seconds": 0.5,
            "reverse_dns_max_ips": 100,
        },
    }

    config_file = Path(__file__).parent.parent / "config.yaml"
    if config_file.exists():
        with open(config_file, "r") as f:
            yaml_config = yaml.safe_load(f) or {}
            if "flags" in yaml_config:
                config_dict["flags"].update(yaml_config["flags"])
            if "enrichment" in yaml_config:
                config_dict["enrichment"].update(yaml_config["enrichment"])

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
        ports: List[int] = []
        for raw_token in ports_str.split(","):
            token = raw_token.strip()
            if not token:
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

    env_enrichment_enabled = os.getenv("ENRICHMENT_ENABLED")
    if env_enrichment_enabled is not None and env_enrichment_enabled != "":
        config_dict["enrichment"]["enabled"] = parse_bool_env(
            "ENRICHMENT_ENABLED",
            env_enrichment_enabled,
        )

    env_reverse_enabled = os.getenv("ENRICHMENT_REVERSE_DNS_ENABLED")
    if env_reverse_enabled is not None and env_reverse_enabled != "":
        config_dict["enrichment"]["reverse_dns_enabled"] = parse_bool_env(
            "ENRICHMENT_REVERSE_DNS_ENABLED",
            env_reverse_enabled,
        )

    env_reverse_timeout = os.getenv("ENRICHMENT_REVERSE_DNS_TIMEOUT_SECONDS")
    if env_reverse_timeout is not None and env_reverse_timeout != "":
        try:
            timeout_val = float(env_reverse_timeout)
        except ValueError as exc:
            raise ValueError(
                "Invalid configuration: ENRICHMENT_REVERSE_DNS_TIMEOUT_SECONDS="
                f"'{env_reverse_timeout}' must be a positive number."
            ) from exc
        if timeout_val <= 0:
            raise ValueError(
                "Invalid configuration: ENRICHMENT_REVERSE_DNS_TIMEOUT_SECONDS="
                f"'{env_reverse_timeout}' must be greater than 0."
            )
        config_dict["enrichment"]["reverse_dns_timeout_seconds"] = timeout_val

    env_reverse_max = os.getenv("ENRICHMENT_REVERSE_DNS_MAX_IPS")
    if env_reverse_max is not None and env_reverse_max != "":
        try:
            max_ips = int(env_reverse_max)
        except ValueError as exc:
            raise ValueError(
                "Invalid configuration: ENRICHMENT_REVERSE_DNS_MAX_IPS="
                f"'{env_reverse_max}' must be an integer greater than or equal to 0."
            ) from exc
        if max_ips < 0:
            raise ValueError(
                "Invalid configuration: ENRICHMENT_REVERSE_DNS_MAX_IPS="
                f"'{env_reverse_max}' must be greater than or equal to 0."
            )
        config_dict["enrichment"]["reverse_dns_max_ips"] = max_ips

    return Settings(**config_dict)


settings = load_config()
