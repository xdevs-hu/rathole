"""
Config presets — deployment profiles for Rathole nodes.

Every preset now includes LoRa-specific filters (lora_snr, lora_airtime).
These filters are self-selecting no-ops on TCP/I2P interfaces — they only
activate when a packet arrives on a LoRa interface (SNR present, bitrate
< 50 Kbps, or RNodeInterface class name). No separate "lora" or
"gateway_lora" preset is needed.

Presets (lightest → strictest):
  observe   — Dry-run, learn traffic patterns for 24h, publishes to registry
  relaxed   — Minimal interference, observe first, auto-connects to gateways
  balanced  — Active defense, fair limits, adaptive learning (recommended)
  standard  — Good defaults for most users (recommended for smaller nodes)
  strict    — Tight security, low hop ceiling, manual peering only
  fortress  — Zero tolerance, auto-blackhole, defensive correlator

The node_mode field (gateway/client) is kept in each preset as a hint for
the registry announce payload and TUI badge — it no longer gates which
presets are shown.
"""

import copy
import logging

from .config import DEFAULT_CONFIG, _deep_merge

log = logging.getLogger("rathole.presets")


# ── Shared LoRa filter blocks per security tier ──────────────────
#
# These are merged into every preset so LoRa interfaces are always
# handled correctly regardless of which preset is active.
# On TCP/I2P the filters are no-ops (ctx.snr is None / bitrate too high).

_LORA_OBSERVE = {
    "lora_snr": {
        "enabled": True,
        "min_snr": -15.0,   # Very permissive — just flag, don't drop
        "min_rssi": None,
        "action": "flag",
    },
    "lora_airtime": {
        "enabled": True,
        "duty_cycle_percent": 1.0,
        "window_seconds": 3600,
        "spreading_factor": 8,
        "bandwidth_hz": 125_000,
    },
}

_LORA_RELAXED = {
    "lora_snr": {
        "enabled": True,
        "min_snr": -12.0,
        "min_rssi": None,
        "action": "flag",   # Observe first — flag but don't drop
    },
    "lora_airtime": {
        "enabled": True,
        "duty_cycle_percent": 1.0,
        "window_seconds": 3600,
        "spreading_factor": 8,
        "bandwidth_hz": 125_000,
    },
}

_LORA_BALANCED = {
    "lora_snr": {
        "enabled": True,
        "min_snr": -10.0,
        "min_rssi": None,
        "action": "drop",
    },
    "lora_airtime": {
        "enabled": True,
        "duty_cycle_percent": 1.0,
        "window_seconds": 3600,
        "spreading_factor": 8,
        "bandwidth_hz": 125_000,
    },
}

_LORA_STRICT = {
    "lora_snr": {
        "enabled": True,
        "min_snr": -7.0,    # Tighter SNR gate
        "min_rssi": None,
        "action": "drop",
    },
    "lora_airtime": {
        "enabled": True,
        "duty_cycle_percent": 1.0,
        "window_seconds": 3600,
        "spreading_factor": 8,
        "bandwidth_hz": 125_000,
    },
}

_LORA_FORTRESS = {
    "lora_snr": {
        "enabled": True,
        "min_snr": -5.0,    # Only strong signals accepted
        "min_rssi": None,
        "action": "drop",
    },
    "lora_airtime": {
        "enabled": True,
        "duty_cycle_percent": 0.5,  # Half the legal limit — extra headroom
        "window_seconds": 3600,
        "spreading_factor": 8,
        "bandwidth_hz": 125_000,
    },
}

_LORA_SECTION_BALANCED = {
    "enabled": True,
    "duty_cycle_percent": 1.0,
    "duty_cycle_window": 3600,
    "min_snr": -10.0,
    "spreading_factor": 8,
    "bandwidth_hz": 125_000,
}

_LORA_SECTION_STRICT = {
    "enabled": True,
    "duty_cycle_percent": 1.0,
    "duty_cycle_window": 3600,
    "min_snr": -7.0,
    "spreading_factor": 8,
    "bandwidth_hz": 125_000,
}

_LORA_SECTION_FORTRESS = {
    "enabled": True,
    "duty_cycle_percent": 0.5,
    "duty_cycle_window": 3600,
    "min_snr": -5.0,
    "spreading_factor": 8,
    "bandwidth_hz": 125_000,
}

_LORA_SECTION_OBSERVE = {
    "enabled": True,
    "duty_cycle_percent": 1.0,
    "duty_cycle_window": 3600,
    "min_snr": -15.0,
    "spreading_factor": 8,
    "bandwidth_hz": 125_000,
}

_LORA_SECTION_RELAXED = {
    "enabled": True,
    "duty_cycle_percent": 1.0,
    "duty_cycle_window": 3600,
    "min_snr": -12.0,
    "spreading_factor": 8,
    "bandwidth_hz": 125_000,
}


# ── Presets ──────────────────────────────────────────────────────

_OBSERVE: dict = {
    "general": {
        "node_mode": "gateway",
        "dry_run": True,  # Observe for 24h before blocking
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 64},
        "rate_limit": {"enabled": True, "refill_rate": 1.0, "burst": 30, "overflow_action": "drop"},
        "churn": {"enabled": False, "suppress_threshold": 20.0, "reuse_threshold": 5.0, "decay_interval": 120},
        "anomaly": {"enabled": True, "anomaly_action": "flag", "max_announce_ratio": 100.0, "min_packets": 100},
        "interface_rate": {"enabled": True, "refill_rate": 50.0, "burst": 200},
        "bandwidth": {"enabled": True, "bytes_per_second": 2_000_000, "burst_bytes": 4_000_000},
        "packet_size": {"enabled": True, "max_bytes": 600},
        "announce_size": {"enabled": True, "max_app_data_bytes": 500},
        "path_request": {"enabled": True, "max_per_minute": 100, "scan_threshold": 50, "scan_window": 60},
        "link_request": {"enabled": True, "refill_rate": 2.0, "burst": 20, "max_pending_per_interface": 100},
        "resource_guard": {"enabled": True, "max_resource_bytes": 33_554_432, "max_active_per_interface": 20},
        **_LORA_OBSERVE,
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": True, "learning_hours": 24},
    "correlator": {"enabled": True, "sybil_threshold": 100, "response_mode": "alert", "grace_period": 600},
    "metrics": {"enabled": True},
    "eventstore": {"enabled": True},
    "registry": {"enabled": True, "publish": True, "discover": True, "auto_connect": False},
    "lora": _LORA_SECTION_OBSERVE,
}

_RELAXED: dict = {
    "general": {
        "node_mode": "client",
        "dry_run": True,  # Observe first
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 64},
        "rate_limit": {"enabled": True, "refill_rate": 1.0, "burst": 30, "overflow_action": "drop"},
        "churn": {"enabled": False, "suppress_threshold": 20.0, "reuse_threshold": 5.0, "decay_interval": 120},
        "anomaly": {"enabled": True, "anomaly_action": "flag", "max_announce_ratio": 100.0, "min_packets": 100},
        "interface_rate": {"enabled": True, "refill_rate": 20.0, "burst": 100},
        "bandwidth": {"enabled": True, "bytes_per_second": 1_000_000, "burst_bytes": 2_000_000},
        "packet_size": {"enabled": True, "max_bytes": 600},
        "announce_size": {"enabled": True, "max_app_data_bytes": 500},
        "path_request": {"enabled": True, "max_per_minute": 60, "scan_threshold": 50, "scan_window": 60},
        "link_request": {"enabled": True, "refill_rate": 2.0, "burst": 20, "max_pending_per_interface": 100},
        "resource_guard": {"enabled": True, "max_resource_bytes": 33_554_432, "max_active_per_interface": 20},
        **_LORA_RELAXED,
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": False},
    "correlator": {"enabled": True, "sybil_threshold": 100, "response_mode": "alert", "grace_period": 600},
    "registry": {"enabled": True, "publish": False, "discover": True, "auto_connect": True, "max_auto_connect": 5},
    "lora": _LORA_SECTION_RELAXED,
}

_BALANCED: dict = {
    "general": {
        "node_mode": "gateway",
        "dry_run": False,
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 64},
        "rate_limit": {"enabled": True, "refill_rate": 1.0, "burst": 30},
        "churn": {"enabled": False, "suppress_threshold": 15.0, "reuse_threshold": 3.0, "decay_interval": 120},
        "anomaly": {"enabled": True, "anomaly_action": "throttle", "max_announce_ratio": 75.0, "min_packets": 50},
        "interface_rate": {"enabled": True, "refill_rate": 30.0, "burst": 100},
        "bandwidth": {"enabled": True, "bytes_per_second": 1_500_000, "burst_bytes": 3_000_000},
        "packet_size": {"enabled": True, "max_bytes": 600},
        "announce_size": {"enabled": True, "max_app_data_bytes": 500},
        "path_request": {"enabled": True, "max_per_minute": 60, "scan_threshold": 30, "scan_window": 60},
        "link_request": {"enabled": True, "refill_rate": 2.0, "burst": 20, "max_pending_per_interface": 100},
        "resource_guard": {"enabled": True, "max_resource_bytes": 33_554_432, "max_active_per_interface": 20},
        **_LORA_BALANCED,
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": True, "learning_hours": 12},
    "correlator": {"enabled": True, "sybil_threshold": 50, "response_mode": "alert", "grace_period": 300},
    "metrics": {"enabled": True},
    "eventstore": {"enabled": True},
    "registry": {"enabled": True, "publish": True, "discover": True, "auto_connect": False},
    "lora": _LORA_SECTION_BALANCED,
}

_STANDARD: dict = {
    "general": {
        "node_mode": "client",
        "dry_run": False,
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 32},
        "rate_limit": {"enabled": True, "refill_rate": 0.5, "burst": 15},
        "churn": {"enabled": False, "suppress_threshold": 15.0, "reuse_threshold": 3.0, "decay_interval": 120},
        "anomaly": {"enabled": True, "anomaly_action": "flag", "max_announce_ratio": 75.0, "min_packets": 50},
        "interface_rate": {"enabled": True, "refill_rate": 10.0, "burst": 50},
        "bandwidth": {"enabled": True, "bytes_per_second": 500_000, "burst_bytes": 1_000_000},
        "packet_size": {"enabled": True, "max_bytes": 600},
        "announce_size": {"enabled": True, "max_app_data_bytes": 500},
        "path_request": {"enabled": True, "max_per_minute": 30, "scan_threshold": 20, "scan_window": 60},
        "link_request": {"enabled": True, "refill_rate": 1.0, "burst": 10, "max_pending_per_interface": 50},
        "resource_guard": {"enabled": True, "max_resource_bytes": 16_777_216, "max_active_per_interface": 10},
        **_LORA_BALANCED,
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": True, "learning_hours": 12},
    "correlator": {"enabled": True, "sybil_threshold": 50, "response_mode": "alert", "grace_period": 300},
    "registry": {"enabled": True, "publish": False, "discover": True, "auto_connect": True, "max_auto_connect": 5},
    "lora": _LORA_SECTION_BALANCED,
}

_STRICT: dict = {
    "general": {
        "node_mode": "client",
        "dry_run": False,
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 16},
        "rate_limit": {"enabled": True, "refill_rate": 0.2, "burst": 8, "overflow_action": "drop"},
        "churn": {"enabled": True, "suppress_threshold": 8.0, "reuse_threshold": 2.0, "penalty_per_announce": 2.0},
        "anomaly": {"enabled": True, "anomaly_action": "throttle", "max_announce_ratio": 30.0, "min_packets": 25},
        "interface_rate": {"enabled": True, "refill_rate": 5.0, "burst": 25, "overflow_action": "drop"},
        "bandwidth": {"enabled": True, "bytes_per_second": 250_000, "burst_bytes": 500_000},
        "packet_size": {"enabled": True, "max_bytes": 500},
        "announce_size": {"enabled": True, "max_app_data_bytes": 300},
        "path_request": {"enabled": True, "max_per_minute": 15, "scan_threshold": 10, "scan_window": 30},
        "link_request": {"enabled": True, "refill_rate": 0.5, "burst": 5, "max_pending_per_interface": 20},
        "resource_guard": {"enabled": True, "max_resource_bytes": 8_388_608, "max_active_per_interface": 5},
        **_LORA_STRICT,
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": True, "learning_hours": 6, "alert_sigma": 2.5, "block_sigma": 4.0},
    "correlator": {"enabled": True, "sybil_threshold": 20, "response_mode": "alert", "grace_period": 120},
    "registry": {"enabled": True, "publish": False, "discover": True, "auto_connect": False},
    "lora": _LORA_SECTION_STRICT,
}

_FORTRESS: dict = {
    "general": {
        "node_mode": "gateway",
        "dry_run": False,
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 32},
        "rate_limit": {"enabled": True, "refill_rate": 0.3, "burst": 10, "overflow_action": "drop"},
        "churn": {"enabled": True, "suppress_threshold": 8.0, "reuse_threshold": 2.0, "penalty_per_announce": 2.0},
        "anomaly": {"enabled": True, "anomaly_action": "drop", "max_announce_ratio": 20.0, "min_packets": 25},
        "interface_rate": {"enabled": True, "refill_rate": 20.0, "burst": 50, "overflow_action": "drop"},
        "bandwidth": {"enabled": True, "bytes_per_second": 1_000_000, "burst_bytes": 2_000_000},
        "packet_size": {"enabled": True, "max_bytes": 500},
        "announce_size": {"enabled": True, "max_app_data_bytes": 300},
        "path_request": {"enabled": True, "max_per_minute": 30, "scan_threshold": 15, "scan_window": 30},
        "link_request": {"enabled": True, "refill_rate": 1.0, "burst": 10, "max_pending_per_interface": 50},
        "resource_guard": {"enabled": True, "max_resource_bytes": 16_777_216, "max_active_per_interface": 10},
        **_LORA_FORTRESS,
    },
    "reputation": {"enabled": True, "auto_blackhole": True, "auto_blackhole_score": 0.2},
    "adaptive": {"enabled": True, "learning_hours": 6, "alert_sigma": 2.5, "block_sigma": 4.0},
    "correlator": {"enabled": True, "sybil_threshold": 20, "amplification_ratio": 5.0, "response_mode": "defensive", "grace_period": 120},
    "metrics": {"enabled": True},
    "eventstore": {"enabled": True},
    "registry": {"enabled": True, "publish": False, "discover": True, "auto_connect": False},
    "lora": _LORA_SECTION_FORTRESS,
}


# ── Registry ─────────────────────────────────────────────────────

PRESETS: dict[str, dict] = {
    "observe":   _OBSERVE,
    "relaxed":   _RELAXED,
    "balanced":  _BALANCED,
    "standard":  _STANDARD,
    "strict":    _STRICT,
    "fortress":  _FORTRESS,
}

# All presets shown in a single flat list — no mode gating.
# node_mode inside each preset is a hint for the registry announce
# and TUI badge; it does not restrict which preset can be applied.
ALL_PRESETS: list[str] = ["observe", "relaxed", "balanced", "standard", "strict", "fortress"]

# Kept for backward compatibility — both modes now show all presets.
MODE_PRESETS: dict[str, list[str]] = {
    "gateway": ALL_PRESETS,
    "client":  ALL_PRESETS,
}

# Backward-compatible aliases for old preset names
PRESET_ALIASES: dict[str, str] = {
    # Legacy aliases (pre-v1.0)
    "conservative": "relaxed",
    "moderate": "standard",
    "aggressive": "fortress",
    # Old two-word aliases (v1.0)
    "gateway-observe": "observe",
    "gateway-balanced": "balanced",
    "gateway-fortress": "fortress",
    "client-relaxed": "relaxed",
    "client-balanced": "standard",
    "client-strict": "strict",
    # Removed presets — map to closest equivalent
    "gateway_lora": "balanced",      # gateway+lora → balanced (lora filters now built-in)
    "gateway-lora": "balanced",
    "gateway_lora_bridge": "balanced",
    "lora": "standard",              # lora-only → standard (lora filters now built-in)
}

DESCRIPTIONS: dict[str, str] = {
    "observe":  "Observe first — dry-run ON, generous limits, learn traffic for 24h, publishes to registry. LoRa: flag-only SNR gate.",
    "relaxed":  "Minimal interference — dry-run ON, generous limits, auto-connects to gateways. LoRa: flag-only SNR gate.",
    "balanced": "Active defense — fair limits, adaptive learning, metrics enabled, publishes to registry. LoRa: SNR gate + duty-cycle.",
    "standard": "Good defaults — standard protection, adaptive learning, auto-connects to gateways. LoRa: SNR gate + duty-cycle.",
    "strict":   "Tight security — strict rate limits, low hop ceiling, manual peering only. LoRa: tighter SNR gate (-7 dB).",
    "fortress": "Zero tolerance — auto-blackhole, tight limits, defensive correlator. LoRa: strict SNR gate (-5 dB), 0.5% duty-cycle.",
}

# Human-readable display names for the TUI preset selector.
PRESET_DISPLAY_NAMES: dict[str, str] = {
    "observe":  "Observe",
    "relaxed":  "Relaxed",
    "balanced": "Balanced",
    "standard": "Standard",
    "strict":   "Strict",
    "fortress": "Fortress",
}


def list_presets(mode: str | None = None) -> list[dict]:
    """List available presets.

    The ``mode`` argument is accepted for backward compatibility but is
    ignored — all presets are returned regardless of mode since every
    preset now handles TCP/I2P/LoRa interfaces uniformly.
    """
    return [
        {"name": name, "description": DESCRIPTIONS.get(name, "")}
        for name in ALL_PRESETS
    ]


def apply_preset(name: str) -> dict:
    """
    Generate a full config by merging a preset over the defaults.

    Supports both current names (e.g. "balanced") and legacy aliases
    (e.g. "moderate" → "standard", "gateway_lora" → "balanced").

    Returns the merged config dict, ready to be used as RatholeConfig.raw.
    """
    # Resolve aliases
    resolved = PRESET_ALIASES.get(name, name)

    if resolved not in PRESETS:
        available = list(PRESETS.keys()) + list(PRESET_ALIASES.keys())
        raise ValueError(f"Unknown preset: {name}. Available: {available}")

    preset = PRESETS[resolved]
    merged = _deep_merge(copy.deepcopy(DEFAULT_CONFIG), preset)
    log.info("Applied preset: %s%s", resolved, f" (alias for {name})" if resolved != name else "")
    return merged


def preset_diff(name: str) -> dict:
    """
    Show what a preset changes from defaults.

    Returns a dict of only the values that differ from DEFAULT_CONFIG.
    """
    resolved = PRESET_ALIASES.get(name, name)
    if resolved not in PRESETS:
        raise ValueError(f"Unknown preset: {name}")
    return PRESETS[resolved]
