"""Configuration loading and validation."""

import sys
import tomllib
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger("rathole.config")


def _default_control_socket() -> str:
    """Return the platform-appropriate default control socket address."""
    if sys.platform == "win32":
        return "127.0.0.1:4242"
    return "/tmp/rathole.sock"


# ── Defaults ────────────────────────────────────────────────────

DEFAULT_CONFIG: dict[str, Any] = {
    "general": {
        "node_mode": "client",  # "gateway" or "client"
        "reticulum_config_path": "",
        "dry_run": False,
        "state_persist_interval": 300,
        "state_file": "~/.rathole/state.json",
        "log_level": "INFO",
        "log_file": "",
        "control_socket": _default_control_socket(),
    },
    "filters": {
        # ── Trusted peers (I2P→LoRa gate) — must be first in announce pipeline ──
        # Disabled by default so new installs work out of the box.
        # Enable on LoRa gateway nodes to block internet announce floods from
        # reaching LoRa devices.  peers=[] blocks ALL I2P announces.
        # Add peer hash prefixes to allow specific I2P peers through.
        # lora_max_hops: secondary ceiling for trusted peers (TCP client→VPS→RPi4 = 2 hops).
        "trusted_peers": {
            "enabled": False,     # Enable on LoRa gateway nodes only
            "i2p_only": True,
            "lora_max_hops": 4,   # TCP client→VPS→RPi4 = 2 hops; 4 gives headroom for one relay
            "peers": [],          # empty = block all I2P announces when enabled
        },
        "allowdeny": {
            "enabled": True,
            "allow_destinations": [],
            "allow_peers": [],
            "deny_destinations": [],
            "deny_peers": [],
        },
        "hop_ceiling": {
            "enabled": True,
            "max_hops": 32,  # Reasonable default — blocks deep-chain amplification while allowing normal topologies
        },
        "rate_limit": {
            "enabled": True,
            "refill_rate": 0.5,
            "burst": 15,
            "overflow_action": "drop",
        },
        "churn": {
            "enabled": False,
            "penalty_per_announce": 1.0,
            "decay_factor": 0.5,
            "decay_interval": 120,  # 2 min — quick recovery for normal traffic
            "suppress_threshold": 15.0,  # High enough that normal re-announces don't trigger
            "reuse_threshold": 3.0,
            "max_penalty": 20.0,
        },
        "anomaly": {
            "enabled": True,
            "window": 600,
            "max_announce_ratio": 100.0,  # Quiet networks are announce-heavy; 50 triggers false positives
            "anomaly_action": "flag",  # Flag-only is safer default; presets override for enforcement
            "min_packets": 50,  # Minimum packets in window before ratio is evaluated
            "grace_period": 300,  # Skip evaluation for newly-connected interfaces (initial sync)
        },
        # ── Global filters (all packet types) ────────────────
        "interface_rate": {
            "enabled": True,
            "refill_rate": 10.0,
            "burst": 50,
            "overflow_action": "drop",
        },
        "bandwidth": {
            "enabled": True,
            "bytes_per_second": 500_000,
            "burst_bytes": 1_000_000,
        },
        "packet_size": {
            "enabled": True,
            "max_bytes": 600,
        },
        # ── Type-specific filters ────────────────────────────
        "announce_size": {
            "enabled": True,
            "max_app_data_bytes": 500,
        },
        "path_request": {
            "enabled": True,
            "max_per_minute": 30,
            "scan_threshold": 20,
            "scan_window": 60,
        },
        "link_request": {
            "enabled": True,
            "refill_rate": 1.0,
            "burst": 10,
            "max_pending_per_interface": 50,
        },
        "resource_guard": {
            "enabled": True,
            "max_resource_bytes": 16_777_216,
            "max_active_per_interface": 10,
        },
        # ── LoRa-specific filters ────────────────────────────
        "lora_snr": {
            "enabled": False,
            "min_snr": -10.0,
            "min_rssi": None,
            "action": "drop",
        },
        "lora_airtime": {
            "enabled": False,
            "duty_cycle_percent": 1.0,
            "window_seconds": 3600,
            "spreading_factor": 8,
            "bandwidth_hz": 125_000,
        },
    },
    "reputation": {
        "enabled": True,
        "neutral_score": 0.5,
        "accept_reward": 0.005,  # 5x faster trust building (was 0.001)
        "drop_penalty": 0.015,   # 3:1 ratio instead of 20:1 (was 0.02)
        "throttle_penalty": 0.01,
        "blackhole_penalty": 0.1,
        "scan_penalty": 0.15,
        "decay_rate": 0.02,      # Earned reputation persists longer (was 0.05)
        "auto_blackhole": False,
        "auto_blackhole_score": 0.15,
    },
    "blackhole": {
        "sync_interval": 60,
        "auto_blackhole": False,
        "auto_blackhole_score": 0.15,
    },
    "adaptive": {
        "enabled": False,
        "learning_hours": 6,
        "alert_sigma": 3.0,
        "block_sigma": 5.0,
        "sample_interval": 60,
        "max_samples": 1440,
    },
    "correlator": {
        "enabled": True,
        "interval": 30,
        "sybil_window": 300,
        "sybil_threshold": 50,
        "scan_sequential_threshold": 10,
        "slowloris_ratio": 5.0,
        "amplification_ratio": 50.0,
        "response_mode": "alert",       # "alert" (log only) or "defensive" (auto-respond)
        "response_cooldown": 300,       # Seconds before same pattern re-triggers
        "grace_period": 300,            # Seconds after first seeing an interface before alerting
    },
    "metrics": {
        "enabled": False,
        "bind": "127.0.0.1:9777",
        "per_peer_metrics": True,
    },
    "alerts": {
        "enabled": False,
        "rules": [],
    },
    "eventstore": {
        "enabled": False,
        "db_path": "~/.rathole/events.db",
        "retention_days": 7,
        "max_events": 100_000,
    },
    "registry": {
        "enabled": False,
        "discover_url": "https://registry.ratspeak.org/api/v1",
        "publish": False,
        "discover": True,
        "auto_connect": False,
        "max_auto_connect": 5,
        "announce_interval": 300,
        "discover_interval": 600,
        "node_name": "",
        "capabilities": [],
        "exclude_identities": [],
        "request_timeout": 10,
    },
    "lora": {
        "enabled": False,
        # Duty-cycle enforcement (legal requirement on many LoRa bands)
        "duty_cycle_percent": 1.0,      # EU 868 MHz legal limit: 1% per hour
        "duty_cycle_window": 3600,      # Rolling window in seconds (1 hour)
        # SNR quality gate
        "min_snr": -10.0,               # dB — drop packets below this SNR
        "min_rssi": None,               # dBm — optional RSSI gate (None = disabled)
        "snr_action": "drop",           # "drop" or "flag"
        # Radio parameters used for airtime estimation when bitrate is unknown
        "spreading_factor": 8,          # SF7–SF12
        "bandwidth_hz": 125_000,        # 125 kHz standard
        # TX power cap (informational — enforced at RNS config level)
        "max_tx_power": 17,             # dBm
    },
}


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge overlay into base, preferring overlay values.

    Returns a fully independent copy — no dict in the result shares identity
    with any dict in *base* or *overlay*.  This prevents mutations of the
    returned dict from accidentally modifying DEFAULT_CONFIG or the caller's
    original data structures.
    """
    import copy as _copy
    merged = {}
    # Deep-copy every key from base first so we start with independent objects
    for key, val in base.items():
        merged[key] = _copy.deepcopy(val)
    # Overlay: recursively merge dicts, replace everything else
    for key, val in overlay.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = _copy.deepcopy(val)
    return merged


@dataclass
class RatholeConfig:
    """Parsed and validated configuration."""
    raw: dict = field(default_factory=dict)
    config_path: Optional[Path] = None

    # Convenience accessors
    @property
    def general(self) -> dict:
        return self.raw.get("general", {})

    @property
    def filters(self) -> dict:
        return self.raw.get("filters", {})

    @property
    def metrics(self) -> dict:
        return self.raw.get("metrics", {})

    @property
    def reputation(self) -> dict:
        return self.raw.get("reputation", {})

    @property
    def blackhole(self) -> dict:
        return self.raw.get("blackhole", {})

    @property
    def adaptive(self) -> dict:
        return self.raw.get("adaptive", {})

    @property
    def correlator(self) -> dict:
        return self.raw.get("correlator", {})

    @property
    def alerts(self) -> dict:
        return self.raw.get("alerts", {})

    @property
    def eventstore(self) -> dict:
        return self.raw.get("eventstore", {})

    @property
    def registry(self) -> dict:
        return self.raw.get("registry", {})

    @property
    def lora(self) -> dict:
        return self.raw.get("lora", {})

    @property
    def node_mode(self) -> str:
        return self.general.get("node_mode", "client")

    @property
    def dry_run(self) -> bool:
        return self.general.get("dry_run", False)

    def filter_cfg(self, name: str) -> dict:
        """Get config for a specific filter, with defaults applied."""
        return self.filters.get(name, {})

    def filter_enabled(self, name: str) -> bool:
        return self.filter_cfg(name).get("enabled", False)


VALID_NODE_MODES = ("gateway", "client")


def _validate(raw: dict) -> dict:
    """Validate and clamp config values to safe ranges.

    Logs a warning for each invalid value and replaces it with a safe
    default. Returns the (possibly modified) config dict.
    """
    # ── Node mode ─────────────────────────────────────────────────
    general = raw.get("general", {})
    mode = general.get("node_mode", "client")
    if mode not in VALID_NODE_MODES:
        log.warning(
            "Config [general] node_mode = %r is invalid "
            "(must be 'gateway' or 'client'), defaulting to 'client'",
            mode,
        )
        general["node_mode"] = "client"

    filters = raw.get("filters", {})

    # ── Numeric range checks ─────────────────────────────────────
    _checks = [
        # (section, key, min_val, max_val, default)
        ("rate_limit", "refill_rate", 0.0, None, 0.5),
        ("rate_limit", "burst", 1, None, 15),
        ("interface_rate", "refill_rate", 0.0, None, 10.0),
        ("interface_rate", "burst", 1, None, 50),
        ("hop_ceiling", "max_hops", 1, 128, 32),  # RNS PATHFINDER_M = 128
        ("churn", "decay_factor", 0.01, 0.99, 0.5),
        ("churn", "decay_interval", 1, None, 120),
        ("churn", "suppress_threshold", 0.1, None, 15.0),
        ("churn", "reuse_threshold", 0.0, None, 3.0),
        ("anomaly", "max_announce_ratio", 1.0, None, 100.0),
        ("bandwidth", "bytes_per_second", 1, None, 500_000),
        ("packet_size", "max_bytes", 1, None, 600),
        ("path_request", "max_per_minute", 1, None, 30),
        ("path_request", "scan_threshold", 1, None, 20),
        ("link_request", "refill_rate", 0.0, None, 1.0),
        ("link_request", "burst", 1, None, 10),
        ("link_request", "max_pending_per_interface", 1, None, 50),
        ("resource_guard", "max_resource_bytes", 1, None, 16_777_216),
        ("resource_guard", "max_active_per_interface", 1, None, 10),
        ("announce_size", "max_app_data_bytes", 1, None, 500),
        # LoRa filters
        ("lora_snr", "min_snr", -30.0, 10.0, -10.0),
        ("lora_airtime", "duty_cycle_percent", 0.01, 100.0, 1.0),
        ("lora_airtime", "window_seconds", 60, 86400, 3600),
        ("lora_airtime", "spreading_factor", 7, 12, 8),
    ]

    for section, key, min_val, max_val, default in _checks:
        cfg = filters.get(section, {})
        if key not in cfg:
            continue
        val = cfg[key]
        try:
            val = type(default)(val)
        except (TypeError, ValueError):
            log.warning(
                "Config [filters.%s] %s: invalid type %r, using default %s",
                section, key, val, default,
            )
            cfg[key] = default
            continue

        clamped = val
        if min_val is not None and val < min_val:
            clamped = min_val
        if max_val is not None and val > max_val:
            clamped = max_val

        if clamped != val:
            log.warning(
                "Config [filters.%s] %s = %s out of range, clamped to %s",
                section, key, val, clamped,
            )
            cfg[key] = clamped

    # ── Reputation section ───────────────────────────────────────
    rep = raw.get("reputation", {})
    for key, min_v, max_v, default in [
        ("neutral_score", 0.0, 1.0, 0.5),
        ("accept_reward", 0.0, 1.0, 0.005),
        ("drop_penalty", 0.0, 1.0, 0.015),
        ("auto_blackhole_score", 0.0, 1.0, 0.15),
    ]:
        if key not in rep:
            continue
        val = rep[key]
        try:
            val = float(val)
        except (TypeError, ValueError):
            log.warning("Config [reputation] %s: invalid type, using default %s", key, default)
            rep[key] = default
            continue
        if val < min_v or val > max_v:
            clamped = max(min_v, min(max_v, val))
            log.warning(
                "Config [reputation] %s = %s out of range [%s, %s], clamped to %s",
                key, val, min_v, max_v, clamped,
            )
            rep[key] = clamped

    # ── Auto-blackhole consistency ─────────────────────────────────
    rep = raw.get("reputation", {})
    bh = raw.get("blackhole", {})
    rep_auto = rep.get("auto_blackhole", False)
    bh_auto = bh.get("auto_blackhole", False)
    if rep_auto != bh_auto:
        log.warning(
            "Config [reputation] auto_blackhole=%s and [blackhole] auto_blackhole=%s "
            "disagree — either setting enables auto-blackholing. Set both to the same "
            "value to avoid confusion.",
            rep_auto, bh_auto,
        )

    # ── Registry section ─────────────────────────────────────────
    reg = raw.get("registry", {})
    for key, min_v, max_v, default in [
        ("heartbeat_interval", 60, 3600, 300),
        ("discover_interval", 60, 7200, 600),
        ("max_auto_connect", 1, 20, 3),
        ("request_timeout", 1, 60, 10),
    ]:
        if key not in reg:
            continue
        val = reg[key]
        try:
            val = type(default)(val)
        except (TypeError, ValueError):
            log.warning("Config [registry] %s: invalid type, using default %s", key, default)
            reg[key] = default
            continue
        clamped = max(min_v, min(max_v, val))
        if clamped != val:
            log.warning(
                "Config [registry] %s = %s out of range [%s, %s], clamped to %s",
                key, val, min_v, max_v, clamped,
            )
            reg[key] = clamped

    return raw


def load_config(path: str | Path) -> RatholeConfig:
    """Load config from a TOML file, merging with defaults."""
    path = Path(path)
    if not path.exists():
        log.warning("Config file %s not found, using defaults", path)
        return RatholeConfig(raw=DEFAULT_CONFIG, config_path=None)

    with open(path, "rb") as f:
        user_cfg = tomllib.load(f)

    merged = _deep_merge(DEFAULT_CONFIG, user_cfg)
    merged = _validate(merged)
    log.info("Loaded config from %s", path)
    return RatholeConfig(raw=merged, config_path=path)


def reload_config(current: RatholeConfig) -> RatholeConfig:
    """Hot-reload config from the same path."""
    if current.config_path is None:
        log.warning("No config path to reload from")
        return current
    try:
        return load_config(current.config_path)
    except Exception as e:
        log.error("Config reload failed: %s — keeping current config", e)
        return current


def save_config(config: "RatholeConfig") -> bool:
    """Persist the current in-memory config back to the TOML file on disk.

    Strategy: read the existing on-disk TOML (if any), deep-merge the
    current in-memory config on top of it, then write back only the keys
    that differ from DEFAULT_CONFIG.

    This preserves every setting the user explicitly wrote to the file —
    even values that happen to equal the default — while still keeping the
    file minimal.  Without this merge step, a ``save_config`` call (e.g.
    triggered by "Pin Trusted") would overwrite the entire file with only
    the changed keys, silently discarding all other user settings.

    Returns True on success, False on failure (errors are logged).
    """
    if config.config_path is None:
        log.warning("Cannot save config: no config_path set (started with defaults only)")
        return False

    # ── Step 1: load what is currently on disk ────────────────────
    # We start from the on-disk file so that any keys the user wrote
    # explicitly (even if they equal the default) are preserved.
    on_disk: dict = {}
    if config.config_path.exists():
        try:
            with open(config.config_path, "rb") as _f:
                on_disk = tomllib.load(_f)
        except Exception as _e:
            log.warning("Could not read existing config for merge: %s — will overwrite", _e)

    # ── Step 2: deep-merge in-memory config on top of on-disk ─────
    # config.raw already contains the fully-merged (defaults + user)
    # state, so merging it over on_disk produces a dict that has:
    #   • every key the user wrote to disk (preserved)
    #   • every live change made at runtime (e.g. new trusted peer)
    merged_on_disk = _deep_merge(on_disk, config.raw)

    # ── Step 3: diff against defaults to keep the file minimal ────
    def _diff_from_defaults(current: dict, defaults: dict) -> dict:
        """Return only the keys in *current* that differ from *defaults*."""
        out: dict = {}
        for k, v in current.items():
            dv = defaults.get(k)
            if isinstance(v, dict) and isinstance(dv, dict):
                sub = _diff_from_defaults(v, dv)
                if sub:
                    out[k] = sub
            elif v != dv:
                out[k] = v
        return out

    to_write = _diff_from_defaults(merged_on_disk, DEFAULT_CONFIG)
    toml_text = _simple_toml_dumps(to_write)

    try:
        config.config_path.write_text(toml_text, encoding="utf-8")
        log.info("Config saved to %s", config.config_path)
        return True
    except OSError as e:
        log.error("Failed to save config to %s: %s", config.config_path, e)
        return False


def _simple_toml_dumps(data: dict, _prefix: str = "") -> str:
    """Minimal TOML serialiser for the subset of types used in rathole config.

    Handles: bool, int, float, str, list (of str/int/float), nested dicts
    (rendered as TOML tables).  Does NOT handle dates, inline tables, or
    arrays of tables — none of which appear in rathole's config schema.

    Rules
    -----
    * A ``[section]`` header is emitted only when the section has at least
      one scalar key directly under it.  Pure-container sections (e.g.
      ``[filters]`` that only holds sub-tables like ``[filters.trusted_peers]``)
      are skipped — the leaf sub-table headers are self-sufficient in TOML
      and an empty ``[filters]`` header would be misleading.
    * Sub-tables are always rendered after all scalars in the current section
      so that TOML parsers see a well-formed file.
    * The top-level call (``_prefix=""``) never emits a header for itself.
    """
    lines: list[str] = []
    deferred: list[tuple[str, dict]] = []  # nested tables written after scalars

    for k, v in data.items():
        full_key = f"{_prefix}.{k}" if _prefix else k
        if isinstance(v, dict):
            deferred.append((full_key, v))
        elif isinstance(v, bool):
            lines.append(f"{k} = {'true' if v else 'false'}")
        elif isinstance(v, int):
            lines.append(f"{k} = {v}")
        elif isinstance(v, float):
            lines.append(f"{k} = {v}")
        elif v is None:
            # TOML has no null — skip None values
            pass
        elif isinstance(v, str):
            escaped = v.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{k} = "{escaped}"')
        elif isinstance(v, list):
            items = []
            for item in v:
                if isinstance(item, str):
                    escaped = item.replace("\\", "\\\\").replace('"', '\\"')
                    items.append(f'"{escaped}"')
                elif isinstance(item, bool):
                    items.append("true" if item else "false")
                else:
                    items.append(str(item))
            lines.append(f"{k} = [{', '.join(items)}]")

    # Build the scalar block for this section.
    # Emit a [section] header only when:
    #   1. We are inside a recursive call (_prefix is set), AND
    #   2. There is at least one scalar key at this level.
    # Pure-container sections (only sub-tables) skip the header entirely;
    # their children will emit their own fully-qualified headers.
    result = ""
    if lines and _prefix:
        result = f"\n[{_prefix}]\n"
    result += "\n".join(lines)
    if lines:
        result += "\n"

    # Recurse into sub-tables.  Each sub-table call returns a block that
    # already starts with its own ``\n[full.key]\n`` header (if it has
    # scalars) or directly with its children's headers.
    for full_key, sub in deferred:
        result += _simple_toml_dumps(sub, _prefix=full_key)

    # At the top-level call only, strip a leading newline that arises when
    # the very first section has scalars (its header starts with "\n[...]").
    if not _prefix and result.startswith("\n"):
        result = result[1:]

    return result
