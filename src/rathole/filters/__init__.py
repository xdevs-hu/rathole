"""
Rathole filter modules.

Each filter is a class that implements the BaseFilter interface.
Filters are stateless logic — all mutable state lives in StateTracker.

Filters are organized into registries by pipeline scope:

- GLOBAL_FILTER_REGISTRY: Applied to all packets before type dispatch
- ANNOUNCE_FILTER_REGISTRY: Applied to ANNOUNCE packets only
- PATH_REQUEST_FILTER_REGISTRY: Applied to path requests only
- LINK_REQUEST_FILTER_REGISTRY: Applied to LINKREQUEST packets only
- DATA_FILTER_REGISTRY: Applied to DATA/PROOF packets only
- LORA_FILTER_REGISTRY: Applied to all packets on LoRa interfaces
  (these filters self-skip on non-LoRa interfaces)

The legacy FILTER_REGISTRY is the announce pipeline for backward
compatibility with v0.1.
"""

from .base import BaseFilter

# ── Announce filters (v0.1 originals) ────────────────────────────

from .trusted_peers import TrustedPeerFilter
from .allowdeny import AllowDenyFilter
from .hop_ceiling import HopCeilingFilter
from .rate_limit import RateLimitFilter
from .churn import ChurnDampeningFilter
from .anomaly import AnomalyFilter

# ── New global filters ───────────────────────────────────────────

from .interface_rate import InterfaceRateLimitFilter
from .bandwidth import BandwidthFilter
from .packet_size import PacketSizeFilter

# ── New type-specific filters ────────────────────────────────────

from .announce_size import AnnounceSizeFilter
from .path_request import PathRequestFilter
from .link_request import LinkRequestFilter
from .resource_guard import ResourceGuardFilter

# ── LoRa-specific filters ────────────────────────────────────────

from .lora_airtime import LoRaAirtimeFilter
from .lora_snr import LoRaSNRFilter


# ── Registries ───────────────────────────────────────────────────
#
# Each registry is an ordered list of (config_name, filter_class) tuples.
# Filters execute in this sequence within their pipeline.


GLOBAL_FILTER_REGISTRY: list[tuple[str, type[BaseFilter]]] = [
    ("interface_rate", InterfaceRateLimitFilter),
    ("bandwidth",      BandwidthFilter),
    ("packet_size",    PacketSizeFilter),
    # LoRa filters run globally but self-skip on non-LoRa interfaces
    ("lora_snr",       LoRaSNRFilter),
    ("lora_airtime",   LoRaAirtimeFilter),
]

ANNOUNCE_FILTER_REGISTRY: list[tuple[str, type[BaseFilter]]] = [
    ("trusted_peers",  TrustedPeerFilter),   # Must be first — gates I2P→LoRa before all other filters
    ("allowdeny",      AllowDenyFilter),
    ("hop_ceiling",    HopCeilingFilter),
    ("announce_size",  AnnounceSizeFilter),
    ("rate_limit",     RateLimitFilter),
    ("churn",          ChurnDampeningFilter),
    ("anomaly",        AnomalyFilter),
]

PATH_REQUEST_FILTER_REGISTRY: list[tuple[str, type[BaseFilter]]] = [
    ("path_request",   PathRequestFilter),
]

LINK_REQUEST_FILTER_REGISTRY: list[tuple[str, type[BaseFilter]]] = [
    ("link_request",   LinkRequestFilter),
]

DATA_FILTER_REGISTRY: list[tuple[str, type[BaseFilter]]] = [
    ("resource_guard", ResourceGuardFilter),
]

# Convenience registry for LoRa-specific filters (subset of GLOBAL)
LORA_FILTER_REGISTRY: list[tuple[str, type[BaseFilter]]] = [
    ("lora_snr",       LoRaSNRFilter),
    ("lora_airtime",   LoRaAirtimeFilter),
]

# Legacy alias — the announce pipeline for backward compatibility
FILTER_REGISTRY = ANNOUNCE_FILTER_REGISTRY


__all__ = [
    "BaseFilter",
    # v0.1 filters
    "TrustedPeerFilter",
    "AllowDenyFilter",
    "HopCeilingFilter",
    "RateLimitFilter",
    "ChurnDampeningFilter",
    "AnomalyFilter",
    # New global filters
    "InterfaceRateLimitFilter",
    "BandwidthFilter",
    "PacketSizeFilter",
    # New type-specific filters
    "AnnounceSizeFilter",
    "PathRequestFilter",
    "LinkRequestFilter",
    "ResourceGuardFilter",
    # LoRa filters
    "LoRaAirtimeFilter",
    "LoRaSNRFilter",
    # Registries
    "FILTER_REGISTRY",
    "GLOBAL_FILTER_REGISTRY",
    "ANNOUNCE_FILTER_REGISTRY",
    "PATH_REQUEST_FILTER_REGISTRY",
    "LINK_REQUEST_FILTER_REGISTRY",
    "DATA_FILTER_REGISTRY",
    "LORA_FILTER_REGISTRY",
]
