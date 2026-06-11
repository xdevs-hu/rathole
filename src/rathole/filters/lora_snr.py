"""LoRa SNR (Signal-to-Noise Ratio) quality gate filter.

Drops packets received below a minimum SNR threshold on LoRa interfaces.
Very low SNR packets are likely:
  - Corrupted beyond reliable decoding (even if CRC passed)
  - From nodes at the extreme edge of radio range
  - Causing retransmission storms due to unreliable delivery

This filter is a no-op on non-LoRa interfaces (SNR is None for TCP/UDP).
It never affects TCP/IP traffic.

Typical LoRa SNR ranges:
  - > +5 dB:  Excellent signal, full data rate possible
  -  0 to +5: Good signal
  - -5 to  0: Marginal, some packet loss expected
  - -10 to -5: Poor, significant packet loss
  - < -10 dB: Very poor, near noise floor (LoRa theoretical limit ~-20 dB)

Default threshold of -10 dB is conservative — it only blocks packets
that are almost certainly corrupted or from nodes too far away to be
reliable mesh participants.
"""

import logging

from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity
from ..lora import is_lora_context

log = logging.getLogger("rathole.filters.lora_snr")


class LoRaSNRFilter(BaseFilter):
    """Drop LoRa packets below a minimum SNR threshold.

    Only active when ctx.snr is not None (i.e., packet arrived on a
    LoRa interface that reports SNR). All other interfaces pass through.

    Config keys:
        enabled (bool): Enable this filter. Default: False.
        min_snr (float): Minimum acceptable SNR in dB. Default: -10.0.
        min_rssi (float | None): Optional minimum RSSI in dBm. Default: None (disabled).
        action (str): "drop" or "flag". Default: "drop".
    """

    name = "lora_snr"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._min_snr: float = float(config.get("min_snr", -10.0))
        self._min_rssi: float | None = (
            float(config.get("min_rssi")) if config.get("min_rssi") is not None else None
        )
        self._action: str = config.get("action", "drop")

    def evaluate(self, ctx: PacketContext) -> Verdict:
        # Only apply to LoRa interfaces that report SNR
        if ctx.snr is None:
            return self.accept(ctx)

        # Extra guard: only apply to LoRa-like interfaces
        if not is_lora_context(ctx):
            return self.accept(ctx)

        try:
            # SNR check
            if ctx.snr < self._min_snr:
                reason = (
                    f"LoRa SNR too low on {ctx.interface_name}: "
                    f"{ctx.snr:.1f} dB < {self._min_snr:.1f} dB minimum"
                )
                if self._action == "flag":
                    log.warning("SNR gate (flag only): %s", reason)
                    return self.accept(ctx)
                v = self.drop(ctx, reason=reason)
                v.severity = Severity.NOTICE
                return v

            # RSSI check (optional)
            if self._min_rssi is not None and ctx.rssi is not None:
                if ctx.rssi < self._min_rssi:
                    reason = (
                        f"LoRa RSSI too low on {ctx.interface_name}: "
                        f"{ctx.rssi:.1f} dBm < {self._min_rssi:.1f} dBm minimum"
                    )
                    if self._action == "flag":
                        log.warning("RSSI gate (flag only): %s", reason)
                        return self.accept(ctx)
                    v = self.drop(ctx, reason=reason)
                    v.severity = Severity.NOTICE
                    return v

            return self.accept(ctx)

        except Exception as e:
            log.error("LoRaSNRFilter error (failing open): %s", e)
            return self.accept(ctx)

    def refresh_config(self, config: dict):
        """Hot-reload config values."""
        self._min_snr = float(config.get("min_snr", -10.0))
        self._min_rssi = (
            float(config.get("min_rssi")) if config.get("min_rssi") is not None else None
        )
        self._action = config.get("action", "drop")
