"""Egress policy: re-exported from egresslens.policy, where the engine now lives.

The verdict has to be reachable from `egresslens check` in CI, and the CLI is a
zero-dependency package on a 3.9 floor -- so the engine moved there rather than
the CLI growing fastapi/pydantic to reach it. This module keeps `app.policy`
importable, and is a compatibility seam only: no logic belongs here.
"""
try:
    from egresslens.policy import (  # the egresslens CLI package is a backend dependency
        MAX_RULES,
        MAX_UNEXPECTED,
        AllowRule,
        IPNetwork,
        Policy,
        PolicyError,
        domain_matches,
        evaluate_policy,
        load_policy,
        resolve_destinations,
    )
except ImportError as exc:  # pragma: no cover - install-time failure, not a code path
    raise ImportError(
        "the egresslens CLI package provides the policy engine; install it with "
        "`pip install -e ./cli` from the repo root"
    ) from exc

__all__ = [
    "MAX_RULES",
    "MAX_UNEXPECTED",
    "AllowRule",
    "IPNetwork",
    "Policy",
    "PolicyError",
    "domain_matches",
    "evaluate_policy",
    "load_policy",
    "resolve_destinations",
]
