"""LoRa interface utilities for Rathole.

Detect, configure, and manage LoRa interfaces (RNode, Meshtastic-serial,
and other RNS-compatible LoRa hardware) for use with Reticulum's
RNodeInterface. No runtime RNS dependency except functions that
explicitly lazy-import it.

Supported hardware:
  - RNode (https://unsigned.io/rnode/) — the primary RNS LoRa interface
  - Any serial device supported by RNS RNodeInterface

Typical LoRa parameters for RNode:
  - Frequency: 433 MHz, 868 MHz (EU), 915 MHz (US), 923 MHz (AS)
  - Spreading Factor: 7–12 (higher = longer range, slower)
  - Bandwidth: 125 kHz, 250 kHz, 500 kHz
  - Coding Rate: 4/5, 4/6, 4/7, 4/8
  - TX Power: 2–23 dBm (hardware-dependent; SX1276 max ~20 dBm, SX1262 max ~22 dBm — chip clamps values above its physical limit)
"""

from __future__ import annotations

import glob
import logging
import platform
import re
from pathlib import Path
from typing import Any

log = logging.getLogger("rathole.lora")


# ── LoRa interface type detection ────────────────────────────────

# RNS interface class names that indicate LoRa hardware
_LORA_TYPE_NAMES = frozenset({
    "RNodeInterface",
    "RNodeMultiInterface",
    "LoRaInterface",
    "SerialInterface",   # May be used for LoRa serial bridges
})

# Bitrate threshold: LoRa is always < 50 Kbps; TCP/UDP are >> 100 Kbps
LORA_BITRATE_THRESHOLD = 50_000  # bps


def is_lora_interface(iface) -> bool:
    """Return True if the interface is a LoRa-type interface.

    Checks by class name first (most reliable), then falls back to
    bitrate heuristic (LoRa is always < 50 Kbps).
    """
    type_name = type(iface).__name__
    if type_name in _LORA_TYPE_NAMES:
        return True
    # Bitrate heuristic: LoRa is always very slow
    bitrate = getattr(iface, "bitrate", None)
    if bitrate is not None and 0 < bitrate < LORA_BITRATE_THRESHOLD:
        return True
    return False


def is_lora_context(ctx) -> bool:
    """Return True if a PacketContext came from a LoRa interface.

    Uses SNR presence (only LoRa interfaces set it) or bitrate heuristic.
    """
    if ctx.snr is not None or ctx.rssi is not None:
        return True
    if ctx.interface_bitrate and 0 < ctx.interface_bitrate < LORA_BITRATE_THRESHOLD:
        return True
    return False


# ── Serial port detection ─────────────────────────────────────────

def check_serial_port_available(port: str) -> tuple[bool, str]:
    """Check whether a serial port path exists and can be opened.

    Returns a ``(ok, error_message)`` tuple.  When *ok* is True the port
    is present and not held by another process; *error_message* is empty.
    When *ok* is False *error_message* contains a human-readable reason.

    The check is intentionally lightweight — it only opens the port for
    a fraction of a second to verify access, then closes it immediately.
    It does NOT send any data to the device.

    Typical failure reasons:
      - Port path does not exist (device not plugged in, wrong path)
      - Permission denied (user not in ``dialout`` / ``uucp`` group)
      - Port already held by another process (e.g. rnsd already running)
    """
    import os

    # 1. Path existence check (works without pyserial)
    if not os.path.exists(port):
        return False, f"Serial port not found: {port} — is the device plugged in?"

    # 2. Try to open the port briefly to catch permission / busy errors
    try:
        import serial  # type: ignore
        with serial.Serial(port, baudrate=115200, timeout=0.1):
            pass
        return True, ""
    except ImportError:
        # pyserial not installed — fall back to raw open() for a basic check
        try:
            fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            os.close(fd)
            return True, ""
        except PermissionError:
            return False, (
                f"Permission denied on {port} — "
                "add your user to the 'dialout' group: sudo usermod -aG dialout $USER"
            )
        except OSError as exc:
            return False, f"Cannot open {port}: {exc}"
    except Exception as exc:
        reason = str(exc)
        if "permission" in reason.lower() or "access" in reason.lower():
            return False, (
                f"Permission denied on {port} — "
                "add your user to the 'dialout' group: sudo usermod -aG dialout $USER"
            )
        if "busy" in reason.lower() or "resource" in reason.lower():
            return False, f"{port} is busy — another process (e.g. rnsd) may already be using it"
        return False, f"Cannot open {port}: {exc}"


def detect_serial_ports() -> list[str]:
    """List candidate serial ports for RNode/LoRa hardware.

    Returns a list of port paths sorted by likelihood of being an RNode.
    On Linux: /dev/ttyUSB*, /dev/ttyACM*, /dev/ttyS*
    On macOS: /dev/cu.usbserial-*, /dev/cu.usbmodem*
    On Windows: COM1–COM99
    """
    ports: list[str] = []
    system = platform.system()

    if system == "Linux":
        for pattern in ("/dev/ttyUSB*", "/dev/ttyACM*"):
            ports.extend(sorted(glob.glob(pattern)))
        # Add ttyS only if nothing else found (usually built-in serial)
        if not ports:
            ports.extend(sorted(glob.glob("/dev/ttyS[0-9]*")))

    elif system == "Darwin":
        for pattern in ("/dev/cu.usbserial-*", "/dev/cu.usbmodem*", "/dev/cu.SLAB_USBtoUART*"):
            ports.extend(sorted(glob.glob(pattern)))

    elif system == "Windows":
        # Try COM1–COM99
        import serial.tools.list_ports  # type: ignore
        try:
            ports = [p.device for p in serial.tools.list_ports.comports()]
        except ImportError:
            ports = [f"COM{i}" for i in range(1, 20)]

    return ports


def probe_rnode(port: str, timeout: float = 3.0) -> bool:
    """Try to detect an RNode on the given serial port.

    Sends the RNode identification command and checks for a valid response.
    Returns True if an RNode is detected, False otherwise.

    This is a best-effort probe — it may return False for valid RNodes
    if the device is busy or in an unexpected state.
    """
    try:
        import serial  # type: ignore
        with serial.Serial(port, baudrate=115200, timeout=timeout) as ser:
            # RNode identification: send CMD_IDENTIFY (0x80) framed as KISS
            # KISS frame: 0xC0 [CMD] [DATA] 0xC0
            # RNode CMD_IDENTIFY = 0x80, no data
            ser.write(bytes([0xC0, 0x80, 0xC0]))
            ser.flush()
            response = ser.read(32)
            # RNode responds with a KISS frame containing device info
            # A valid response starts with 0xC0 and contains printable chars
            if response and response[0] == 0xC0 and len(response) > 4:
                return True
    except Exception:
        pass
    return False


# ── Live interface inspection ─────────────────────────────────────

def detect_lora_interfaces() -> list[dict[str, Any]]:
    """Scan running RNS Transport for LoRa interfaces.

    Returns a list of dicts with interface metadata. Lazy-imports RNS.
    Returns empty list if RNS is not running or no LoRa interfaces found.
    """
    results: list[dict[str, Any]] = []
    try:
        import RNS
        for iface in RNS.Transport.interfaces:
            if not is_lora_interface(iface):
                continue
            info: dict[str, Any] = {
                "name": getattr(iface, "name", str(type(iface).__name__)),
                "type": type(iface).__name__,
                "port": getattr(iface, "port", ""),
                "bitrate": getattr(iface, "bitrate", None),
                "online": getattr(iface, "online", False),
                "rssi": getattr(iface, "rssi", None),
                "snr": getattr(iface, "snr", None),
                "airtime_short": getattr(iface, "airtime_short", None),
                "airtime_long": getattr(iface, "airtime_long", None),
                "channel_load_short": getattr(iface, "channel_load_short", None),
                "channel_load_long": getattr(iface, "channel_load_long", None),
            }
            # RNode-specific radio parameters
            for attr in ("frequency", "bandwidth", "txpower", "sf", "cr"):
                val = getattr(iface, attr, None)
                if val is not None:
                    info[attr] = val
            results.append(info)
    except Exception as e:
        log.debug("detect_lora_interfaces: %s", e)
    return results


def get_lora_stats(iface) -> dict[str, Any]:
    """Extract current radio stats from a live LoRa interface.

    Returns a dict with RSSI, SNR, airtime, and channel load.
    All values may be None if the interface does not expose them.
    """
    return {
        "rssi": getattr(iface, "rssi", None),
        "snr": getattr(iface, "snr", None),
        "airtime_short": getattr(iface, "airtime_short", None),   # % last 15s
        "airtime_long": getattr(iface, "airtime_long", None),     # % last 60s
        "channel_load_short": getattr(iface, "channel_load_short", None),
        "channel_load_long": getattr(iface, "channel_load_long", None),
        "bitrate": getattr(iface, "bitrate", None),
        "online": getattr(iface, "online", False),
    }


# ── RNS config management ─────────────────────────────────────────

# Known LoRa frequency presets (Hz)
FREQUENCY_PRESETS: dict[str, int] = {
    "EU 868 MHz": 868_000_000,
    "EU 433 MHz": 433_000_000,
    "US 915 MHz": 915_000_000,
    "AU 915 MHz": 915_000_000,
    "AS 923 MHz": 923_000_000,
    "CN 470 MHz": 470_000_000,
}

# Default radio parameters for RNode
DEFAULT_RNODE_PARAMS: dict[str, Any] = {
    "frequency": 868_000_000,   # Hz — EU 868 MHz
    "bandwidth": 125_000,       # Hz — 125 kHz
    "txpower": 17,              # dBm — safe default; hardware supports 2–23 dBm (chip clamps to its physical max)
    "spreadingfactor": 8,       # SF8 — good balance of range/speed
    "codingrate": 5,            # 4/5 coding rate
}


def detect_lora_in_rns_config(config_file: Path) -> bool:
    """Check if an RNS config file contains any RNodeInterface sections."""
    if not config_file.exists():
        return False
    try:
        text = config_file.read_text()
        return "RNodeInterface" in text or "RNodeMultiInterface" in text
    except OSError:
        return False


def add_rns_rnode_interface(
    config_file: Path,
    name: str,
    port: str,
    frequency: int = DEFAULT_RNODE_PARAMS["frequency"],
    bandwidth: int = DEFAULT_RNODE_PARAMS["bandwidth"],
    txpower: int = DEFAULT_RNODE_PARAMS["txpower"],
    spreadingfactor: int = DEFAULT_RNODE_PARAMS["spreadingfactor"],
    codingrate: int = DEFAULT_RNODE_PARAMS["codingrate"],
    enabled: bool = True,
    mode: str = "access_point",
):
    """Write an RNodeInterface section to an RNS config file.

    Args:
        mode: RNS interface mode — ``"access_point"`` (default, acts as a
              LoRa access point / gateway) or ``"full"`` (full transport node).
              Written as ``mode = <value>`` in the interface section.

    Uses configobj if available, falls back to text append.
    """
    try:
        from configobj import ConfigObj
        cfg = ConfigObj(str(config_file), list_values=False, indent_type='  ')
        if "interfaces" not in cfg:
            cfg["interfaces"] = {}

        iface_cfg = {
            "type": "RNodeInterface",
            "enabled": "yes" if enabled else "no",
            "mode": mode,
            "port": port,
            "frequency": str(frequency),
            "bandwidth": str(bandwidth),
            "txpower": str(txpower),
            "spreadingfactor": str(spreadingfactor),
            "codingrate": str(codingrate),
        }
        cfg["interfaces"][name] = iface_cfg
        cfg.write()
        log.info("Added RNodeInterface %r (mode=%s) to %s", name, mode, config_file)
    except ImportError:
        # Text fallback
        entry = f"\n  [[{name}]]\n"
        entry += "    type = RNodeInterface\n"
        entry += f"    enabled = {'yes' if enabled else 'no'}\n"
        entry += f"    mode = {mode}\n"
        entry += f"    port = {port}\n"
        entry += f"    frequency = {frequency}\n"
        entry += f"    bandwidth = {bandwidth}\n"
        entry += f"    txpower = {txpower}\n"
        entry += f"    spreadingfactor = {spreadingfactor}\n"
        entry += f"    codingrate = {codingrate}\n"

        text = config_file.read_text()
        if "[interfaces]" in text:
            text += entry
        else:
            text += "\n[interfaces]\n" + entry
        config_file.write_text(text)
        log.info("Added RNodeInterface %r (mode=%s) to %s (text fallback)", name, mode, config_file)


def remove_rns_lora_interface(config_file: Path, name: str) -> bool:
    """Remove a named RNodeInterface from an RNS config file.

    Matches by section name first; if not found, falls back to matching
    by port value so interfaces added outside of rathole (e.g. manually
    or by rnsd) are also removed correctly.

    Returns True if the interface was found and removed.
    """
    # Extract port from name "LoRa /dev/ttyACM0" → "/dev/ttyACM0"
    port_hint = name[len("LoRa "):].strip() if name.startswith("LoRa ") else ""

    try:
        from configobj import ConfigObj
        cfg = ConfigObj(str(config_file), list_values=False, indent_type='  ')
        ifaces = cfg.get("interfaces", {})

        # Try exact name match first
        if name in ifaces:
            del ifaces[name]
            cfg.write()
            return True

        # Fallback: find any RNodeInterface section whose port matches
        if port_hint:
            for section_name, section_data in list(ifaces.items()):
                if not isinstance(section_data, dict):
                    continue
                itype = str(section_data.get("type", "")).strip()
                iport = str(section_data.get("port", "")).strip()
                if itype in ("RNodeInterface", "RNodeMultiInterface") and iport == port_hint:
                    del ifaces[section_name]
                    cfg.write()
                    log.info("Removed LoRa interface section %r (port match) from %s", section_name, config_file)
                    return True

        return False
    except ImportError:
        try:
            text = config_file.read_text()
            lines = text.splitlines()
            result = []
            skip = False
            found = False
            current_section = None
            for line in lines:
                stripped = line.strip()
                # Track current subsection name
                if stripped.startswith("[[") and stripped.endswith("]]"):
                    current_section = stripped[2:-2]
                    if current_section == name:
                        skip = True
                        found = True
                        continue
                    # Port-based fallback: peek ahead not feasible in single pass,
                    # so just match by name in text fallback
                    skip = False
                if skip:
                    if stripped.startswith("[[") or (
                        stripped.startswith("[") and not stripped.startswith("[[")
                    ):
                        skip = False
                        result.append(line)
                    continue
                result.append(line)
            if found:
                config_file.write_text("\n".join(result) + "\n")
            return found
        except Exception:
            return False


# ── Airtime calculation ───────────────────────────────────────────

def estimate_lora_airtime_ms(
    payload_bytes: int,
    spreading_factor: int = 8,
    bandwidth_hz: int = 125_000,
    coding_rate: int = 5,
    preamble_symbols: int = 8,
    explicit_header: bool = True,
    low_data_rate_optimize: bool = False,
) -> float:
    """Estimate LoRa on-air time in milliseconds for a given payload.

    Uses the standard LoRa airtime formula from Semtech AN1200.13.

    Args:
        payload_bytes: Number of bytes in the payload
        spreading_factor: LoRa SF (7–12)
        bandwidth_hz: Channel bandwidth in Hz (125000, 250000, 500000)
        coding_rate: Coding rate denominator (5=4/5, 6=4/6, 7=4/7, 8=4/8)
        preamble_symbols: Number of preamble symbols (default 8)
        explicit_header: True if explicit header mode (default)
        low_data_rate_optimize: True if LDRO is enabled (required for SF11/SF12 at 125kHz)

    Returns:
        Estimated airtime in milliseconds.
    """
    import math

    # Symbol duration
    bw_khz = bandwidth_hz / 1000.0
    t_sym = (2 ** spreading_factor) / bw_khz  # ms

    # Preamble duration
    t_preamble = (preamble_symbols + 4.25) * t_sym

    # Payload symbol count
    ih = 0 if explicit_header else 1
    de = 1 if low_data_rate_optimize else 0
    cr = coding_rate - 4  # 4/5 → 1, 4/6 → 2, etc.

    payload_sym_nb = max(
        8,
        8 + math.ceil(
            max(
                8 * payload_bytes - 4 * spreading_factor + 28 + 16 - 20 * ih,
                0,
            ) / (4 * (spreading_factor - 2 * de))
        ) * (cr + 4),
    )

    t_payload = payload_sym_nb * t_sym
    return t_preamble + t_payload


def duty_cycle_window_budget_ms(
    duty_cycle_percent: float,
    window_seconds: int,
) -> float:
    """Return the total allowed on-air time in ms for a duty-cycle window.

    Args:
        duty_cycle_percent: e.g. 1.0 for 1% (EU legal limit on 868 MHz)
        window_seconds: Rolling window size in seconds

    Returns:
        Maximum allowed airtime in milliseconds within the window.
    """
    return (duty_cycle_percent / 100.0) * window_seconds * 1000.0
