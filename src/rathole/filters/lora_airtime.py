"""LoRa duty-cycle / airtime budget filter.

Enforces the legal and practical duty-cycle limit for LoRa interfaces.
Tracks cumulative on-air time per interface using a rolling window and
drops packets that would exceed the configured budget.

Why this matters:
  - EU 868 MHz band: legally limited to 1% duty cycle (36 s/hour)
  - US 915 MHz: no legal limit but good practice to avoid congestion
  - LoRa gateways that ignore duty cycle cause interference and may
    violate radio regulations

The filter is a no-op on non-LoRa interfaces (identified by bitrate
heuristic or SNR presence). It never blocks TCP/IP traffic.

Airtime estimation uses the standard LoRa formula (Semtech AN1200.13):
    t_sym = 2^SF / BW
    t_preamble = (n_preamble + 4.25) * t_sym
    t_payload = n_payload_symbols * t_sym
    airtime = t_preamble + t_payload

When interface bitrate is known, a simpler approximation is used:
    airtime_ms ≈ (payload_bytes * 8) / bitrate * 1000
"""

import time
import collections
import threading
import logging

from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity
from ..lora import is_lora_context, estimate_lora_airtime_ms, LORA_BITRATE_THRESHOLD

log = logging.getLogger("rathole.filters.lora_airtime")


class _AirtimeWindow:
    """Rolling window airtime tracker for one interface.

    Stores (timestamp, airtime_ms) tuples in a deque. Entries older
    than window_seconds are pruned on each check.
    """

    def __init__(self, window_seconds: int, budget_ms: float):
        self.window_seconds = window_seconds
        self.budget_ms = budget_ms
        self._entries: collections.deque[tuple[float, float]] = collections.deque()
        self._lock = threading.Lock()

    def used_ms(self, now: float) -> float:
        """Return total airtime used within the current window."""
        cutoff = now - self.window_seconds
        with self._lock:
            # Prune stale entries
            while self._entries and self._entries[0][0] < cutoff:
                self._entries.popleft()
            return sum(ms for _, ms in self._entries)

    def would_exceed(self, airtime_ms: float, now: float) -> bool:
        """Return True if adding airtime_ms would exceed the budget."""
        return self.used_ms(now) + airtime_ms > self.budget_ms

    def record(self, airtime_ms: float, now: float):
        """Record airtime usage."""
        with self._lock:
            self._entries.append((now, airtime_ms))

    def remaining_ms(self, now: float) -> float:
        """Return remaining airtime budget in ms."""
        return max(0.0, self.budget_ms - self.used_ms(now))


class LoRaAirtimeFilter(BaseFilter):
    """Enforce LoRa duty-cycle budget per interface.

    Tracks cumulative on-air time using a rolling window. Drops packets
    that would cause the interface to exceed its duty-cycle budget.

    Only active on LoRa interfaces (bitrate < 50 Kbps or SNR present).
    TCP/IP interfaces are always passed through.

    Config keys:
        enabled (bool): Enable this filter. Default: False.
        duty_cycle_percent (float): Max duty cycle %. Default: 1.0 (EU legal).
        window_seconds (int): Rolling window size. Default: 3600 (1 hour).
        spreading_factor (int): LoRa SF for airtime estimation. Default: 8.
        bandwidth_hz (int): LoRa BW in Hz for airtime estimation. Default: 125000.
    """

    name = "lora_airtime"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._duty_cycle_percent = float(config.get("duty_cycle_percent", 1.0))
        self._window_seconds = int(config.get("window_seconds", 3600))
        self._sf = int(config.get("spreading_factor", 8))
        self._bw_hz = int(config.get("bandwidth_hz", 125_000))
        # Per-interface airtime windows: {interface_name: _AirtimeWindow}
        self._windows: dict[str, _AirtimeWindow] = {}
        self._lock = threading.Lock()

    def _budget_ms(self) -> float:
        return (self._duty_cycle_percent / 100.0) * self._window_seconds * 1000.0

    def _get_window(self, interface_name: str) -> _AirtimeWindow:
        with self._lock:
            if interface_name not in self._windows:
                self._windows[interface_name] = _AirtimeWindow(
                    self._window_seconds,
                    self._budget_ms(),
                )
            return self._windows[interface_name]

    def _estimate_airtime(self, ctx: PacketContext) -> float:
        """Estimate on-air time in ms for this packet."""
        if ctx.raw_size == 0:
            return 0.0

        # If we know the bitrate, use simple approximation
        if ctx.interface_bitrate and ctx.interface_bitrate > 0:
            return (ctx.raw_size * 8) / ctx.interface_bitrate * 1000.0

        # Fall back to LoRa formula with configured SF/BW
        try:
            return estimate_lora_airtime_ms(
                payload_bytes=ctx.raw_size,
                spreading_factor=self._sf,
                bandwidth_hz=self._bw_hz,
            )
        except Exception:
            # Conservative fallback: assume 100ms per packet
            return 100.0

    def evaluate(self, ctx: PacketContext) -> Verdict:
        # Only apply to LoRa interfaces
        if not is_lora_context(ctx):
            return self.accept(ctx)

        if not ctx.interface_name:
            return self.accept(ctx)

        try:
            airtime_ms = self._estimate_airtime(ctx)
            if airtime_ms <= 0:
                return self.accept(ctx)

            window = self._get_window(ctx.interface_name)
            now = time.monotonic()

            if window.would_exceed(airtime_ms, now):
                remaining = window.remaining_ms(now)
                v = self.drop(
                    ctx,
                    reason=(
                        f"LoRa duty-cycle budget exceeded on {ctx.interface_name} "
                        f"(estimated {airtime_ms:.1f}ms, "
                        f"remaining {remaining:.1f}ms in {self._window_seconds}s window, "
                        f"limit {self._duty_cycle_percent}%)"
                    ),
                )
                v.severity = Severity.WARNING
                return v

            # Accept and record airtime
            window.record(airtime_ms, now)
            return self.accept(ctx)

        except Exception as e:
            log.error("LoRaAirtimeFilter error (failing open): %s", e)
            return self.accept(ctx)

    def refresh_config(self, config: dict):
        """Hot-reload config values."""
        self._duty_cycle_percent = float(config.get("duty_cycle_percent", 1.0))
        self._window_seconds = int(config.get("window_seconds", 3600))
        self._sf = int(config.get("spreading_factor", 8))
        self._bw_hz = int(config.get("bandwidth_hz", 125_000))
        # Rebuild windows with new budget
        new_budget = self._budget_ms()
        with self._lock:
            for w in self._windows.values():
                w.budget_ms = new_budget
                w.window_seconds = self._window_seconds

    def summary(self) -> dict:
        """Return per-interface airtime usage summary."""
        now = time.monotonic()
        result = {}
        with self._lock:
            for name, window in self._windows.items():
                used = window.used_ms(now)
                result[name] = {
                    "used_ms": round(used, 1),
                    "budget_ms": round(window.budget_ms, 1),
                    "remaining_ms": round(max(0.0, window.budget_ms - used), 1),
                    "used_pct": round(used / window.budget_ms * 100, 2) if window.budget_ms > 0 else 0.0,
                }
        return result
