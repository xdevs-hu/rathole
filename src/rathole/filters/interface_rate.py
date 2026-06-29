"""Per-interface global packet rate limiter.

Limits the total number of packets (all types) accepted from a single
interface per second. This is the first line of defense — it runs in
the global pipeline before type-specific filters and catches raw
volume attacks regardless of packet type.

Protects against packet-count floods (many small packets). Complements
the bandwidth filter which counts bytes. RNS has no native per-interface
packet rate limiting.

I2P interface exemption (default: enabled)
------------------------------------------
I2P interfaces are exempt from this rate limit by default because:

  1. i2pd and the SAM protocol already enforce their own rate limits
     and connection caps at the tunnel layer.

  2. An I2P interface aggregates traffic from ALL I2P peers through a
     single RNS interface object.  A single token bucket shared across
     all peers is too coarse — it exhausts quickly under normal load
     and drops packets that should be forwarded to LoRa.

  3. Dropping I2P inbound packets here prevents I2P→LoRa bridging:
     the packet never reaches _original_inbound() and RNS never gets
     to re-propagate it to the LoRa interface.

Set ``exempt_i2p = false`` in config to re-enable rate limiting on
I2P interfaces (e.g. if you are running a high-traffic public gateway
and need to cap I2P ingress explicitly).
"""

from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity


class InterfaceRateLimitFilter(BaseFilter):
    name = "interface_rate"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._refill_rate = config.get("refill_rate", 10.0)
        self._burst = config.get("burst", 50)
        self._overflow = config.get("overflow_action", "drop")
        # Exempt I2P interfaces from the per-interface packet rate limit.
        # I2P traffic is already rate-limited by i2pd/SAM; applying a
        # coarse single-bucket limit here drops packets before they can
        # be forwarded to LoRa.  Default: True (exempt).
        self._exempt_i2p = bool(config.get("exempt_i2p", True))

    @staticmethod
    def _is_i2p_interface(interface_name: str) -> bool:
        """Return True if the interface name indicates an I2P interface."""
        return "I2P" in interface_name or "i2p" in interface_name.lower()

    def evaluate(self, ctx: PacketContext) -> Verdict:
        if not ctx.interface_name:
            return self.accept(ctx)

        # Exempt I2P interfaces by default — see module docstring.
        if self._exempt_i2p and self._is_i2p_interface(ctx.interface_name):
            return self.accept(ctx)

        self.state.init_interface_bucket(
            ctx.interface_name,
            capacity=self._burst,
            refill_rate=self._refill_rate,
        )

        iface = self.state.get_interface(ctx.interface_name)
        if iface.packet_bucket and iface.packet_bucket.consume(1.0):
            return self.accept(ctx)

        reason = f"interface {ctx.interface_name} packet rate exceeded"
        if self._overflow == "throttle":
            return self.throttle(ctx, reason=reason)
        v = self.drop(ctx, reason=reason)
        v.severity = Severity.WARNING
        return v
