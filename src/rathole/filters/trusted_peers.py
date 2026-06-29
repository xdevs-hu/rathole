"""Trusted peers filter — controls which I2P announces reach LoRa.

When ``i2p_only = true`` (default), this filter only activates on announces
arriving from I2P interfaces.  Announces from LoRa and TCP interfaces pass
through unchanged so existing filtering (allowdeny, hop_ceiling, etc.) still
applies to them.

Behaviour
---------
* ``peers = []`` (empty, default)
    Block ALL I2P announces.  Use this on an RPi4 LoRa gateway to prevent
    internet-side announces from flooding LoRa devices.

* ``peers = ["6cuklfwz", "aabbccdd"]``
    Only allow announces whose ``peer_hash`` starts with one of the listed
    prefixes.  All other I2P announces are dropped.  Prefixes can be the
    full hash or just the first 8 characters (the short B32 prefix).

    For ANNOUNCE packets, ``peer_hash`` equals the announcing destination's
    RNS identity hash (set by the hook so per-peer tracking works correctly
    in hub topologies where all announces share one interface identity).
    Use the hash shown in the TUI Peers tab — the first 16 chars are enough.

* ``lora_max_hops`` (default 4)
    Secondary guard: even for trusted peers, drop announces whose hop count
    exceeds this value.  Prevents stale deep-network announces from reaching
    LoRa devices.  Only evaluated when ``peers`` is non-empty (with an empty
    peers list every I2P announce is dropped before the hop check runs).

* ``i2p_only = false``
    Apply the same peer-whitelist logic to ALL interfaces, not just I2P.
    Rarely needed; leave at ``true`` for normal LoRa gateway use.

Pipeline position
-----------------
Must be **first** in ``ANNOUNCE_FILTER_REGISTRY`` so it can short-circuit
before allowdeny, hop_ceiling, rate_limit, etc.  The ``__init__.py``
registration enforces this order.
"""

from .base import BaseFilter, AnnounceContext
from ..verdicts import Verdict


def _is_i2p_interface(interface_name: str) -> bool:
    """Return True if *interface_name* indicates an I2P interface.

    Matches both the long rnsd form ("I2P Peer xxxxxxxx to full.b32.i2p")
    and the short class-name form ("I2PInterface").
    """
    n = interface_name or ""
    return "I2P" in n or "i2p" in n.lower()


def _peer_matches(peer_hash: str, trusted: set) -> bool:
    """Return True if *peer_hash* starts with any prefix in *trusted*.

    Supports both full hashes and short 8-character prefixes so operators
    can use either form in the config.
    """
    if not peer_hash or not trusted:
        return False
    for prefix in trusted:
        if peer_hash.startswith(prefix):
            return True
    return False


class TrustedPeerFilter(BaseFilter):
    """Gate I2P announces by peer whitelist and hop ceiling.

    Config keys
    -----------
    enabled : bool
        Master switch.  Default ``true``.
    i2p_only : bool
        Only apply to I2P interfaces.  Default ``true``.
    lora_max_hops : int
        Maximum hop count for announces from trusted I2P peers.  Default 4.
        Ignored when ``peers`` is empty (all I2P announces are dropped first).
    peers : list[str]
        Whitelist of RNS identity hash prefixes (full or first 8–16 hex chars).
        For ANNOUNCE packets peer_hash == destination_hash (the announcing
        identity).  Use the hash shown in the TUI Peers tab.
        Empty list (default) blocks ALL I2P announces.
    """

    name = "trusted_peers"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._i2p_only: bool = config.get("i2p_only", True)
        self._lora_max_hops: int = int(config.get("lora_max_hops", 4))
        # Normalise to a frozenset for O(1) prefix lookups
        self._peers: frozenset[str] = frozenset(
            str(p).strip().lower() for p in config.get("peers", []) if p
        )

    def evaluate(self, ctx: AnnounceContext) -> Verdict:
        # Only act on ANNOUNCE packets
        if not ctx.is_announce:
            return self.accept(ctx)

        # If i2p_only, skip non-I2P interfaces entirely — LoRa/TCP unaffected
        if self._i2p_only and not _is_i2p_interface(ctx.interface_name):
            return self.accept(ctx)

        # Trusted peer bypass — always allow whitelisted peers (subject to hop check).
        # For ANNOUNCE packets ctx.peer_hash == ctx.destination_hash (the announcing
        # RNS identity hash).  This is what the TUI Peers tab displays and what
        # "Pin Trusted" stores as a 16-char prefix.
        if self._peers:
            peer = (ctx.peer_hash or "").lower()
            if _peer_matches(peer, self._peers):
                # Secondary hop ceiling for trusted peers
                if ctx.hop_count > self._lora_max_hops:
                    return self.drop(
                        ctx,
                        reason=(
                            f"trusted I2P peer {ctx.peer_hash[:16]} hop count "
                            f"{ctx.hop_count} exceeds lora_max_hops {self._lora_max_hops}"
                        ),
                    )
                return self.accept(ctx)
            # Non-empty peers list but this peer is not in it
            return self.drop(
                ctx,
                reason=(
                    f"I2P peer {ctx.peer_hash[:16] if ctx.peer_hash else '?'} "
                    "not in trusted_peers list"
                ),
            )

        # peers list is empty → block ALL I2P announces
        return self.drop(
            ctx,
            reason="I2P announce blocked: trusted_peers.peers is empty (no trusted I2P peers configured)",
        )
