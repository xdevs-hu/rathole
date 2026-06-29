"""Generic packet size filter.

Drops any packet exceeding a configurable maximum raw size. Applies
only to LoRa inbound packets by default, because:

  - LoRa has a hard MTU of ~500 bytes enforced by the radio hardware.
    Oversized packets on LoRa are always malformed or crafted.

  - I2P and TCP inbound packets may legitimately exceed 500 bytes due
    to SAM protocol framing, tunnel headers, and I2P encapsulation
    overhead.  RNS handles fragmentation before forwarding to LoRa, so
    dropping these at the Rathole layer prevents valid I2P→LoRa
    bridging from working.

  - Setting ``lora_only = false`` in config restores the original
    behaviour (cap applied to all interfaces) for operators who want
    strict global enforcement.

Why not redundant with RNS: Reticulum enforces MTU at pack() on
OUTBOUND packets only. Inbound packets are NOT size-checked before
parsing. This filter catches oversized inbound LoRa packets before RNS
spends CPU parsing them.
"""

from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity
from ..lora import is_lora_context, LORA_BITRATE_THRESHOLD


class PacketSizeFilter(BaseFilter):
    name = "packet_size"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        # Default: 600 bytes (MTU 500 + generous header margin)
        self._max_size = config.get("max_bytes", 600)
        # When True (default), only enforce the cap on LoRa inbound packets.
        # I2P/TCP packets are passed through so RNS can fragment them before
        # forwarding to LoRa.  Set to False to enforce globally.
        self._lora_only = bool(config.get("lora_only", True))

    def _is_i2p_interface(self, ctx: PacketContext) -> bool:
        """Return True if the packet arrived on an I2P interface."""
        iname = ctx.interface_name or ""
        return "I2P" in iname or "i2p" in iname.lower()

    def evaluate(self, ctx: PacketContext) -> Verdict:
        # In lora_only mode (default), only enforce the size cap on LoRa inbound
        # packets.  I2P and TCP packets may legitimately exceed the LoRa MTU due
        # to SAM framing and tunnel overhead; RNS handles fragmentation before
        # forwarding to LoRa, so dropping them here breaks I2P→LoRa bridging.
        if self._lora_only and not is_lora_context(ctx):
            return self.accept(ctx)

        if ctx.raw_size > self._max_size:
            v = self.drop(
                ctx,
                reason=f"packet too large ({ctx.raw_size} > {self._max_size} bytes)",
            )
            v.severity = Severity.WARNING
            return v

        return self.accept(ctx)
