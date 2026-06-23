"""
Rathole daemon — main runtime.

Initializes Reticulum, installs the announce filter hook, and runs
periodic maintenance tasks (state persistence, penalty decay, pruning).
"""

import time
import signal
import logging
import threading
from pathlib import Path

from .config import RatholeConfig, reload_config, save_config
from .state import StateTracker
from .router import PipelineRouter
from .hook import install_hook, uninstall_hook
from .reputation import ReputationEngine
from .blackhole import BlackholeManager
from .adaptive import AdaptiveEngine
from .correlator import AttackCorrelator
from .events import EventBus, SecurityEvent, EventType, EventSeverity
from .eventstore import EventStore
from .metrics import MetricsServer
from .alerts import AlertEngine
from .registry import RegistryClient

log = logging.getLogger("rathole.daemon")


def _default_rns_dir() -> Path:
    """Return the default Reticulum config directory.

    Falls back to ``/var/lib/rathole/.reticulum`` when the process has no
    home directory (e.g. a system user created without ``-m`` in Docker).
    """
    try:
        return Path.home() / ".reticulum"
    except RuntimeError:
        return Path("/var/lib/rathole/.reticulum")


class RatholeDaemon:
    """
    Main daemon process.

    Lifecycle:
        1. Load config
        2. Initialize Reticulum instance
        3. Build filter pipeline
        4. Install Transport hook
        5. Run maintenance loop until shutdown
    """

    # Map correlator AttackPattern names to SecurityEvent types.
    _CORRELATOR_EVENT_MAP = {
        "SYBIL_CLUSTER":    (EventType.SYBIL_DETECTED,          EventSeverity.ALERT),
        "AMPLIFICATION":    (EventType.AMPLIFICATION_DETECTED,   EventSeverity.WARNING),
        "SLOWLORIS_LINK":   (EventType.SLOWLORIS_DETECTED,      EventSeverity.ALERT),
        "DESTINATION_SCAN": (EventType.SCAN_DETECTED,            EventSeverity.ALERT),
    }

    def __init__(self, config: RatholeConfig):
        self.config = config
        self.state = StateTracker()
        self.event_bus = EventBus()
        self.reputation = ReputationEngine(config.reputation)
        self.blackhole = BlackholeManager(config.blackhole)
        self.router = PipelineRouter(
            config, self.state,
            reputation=self.reputation,
            event_bus=self.event_bus,
            blackhole=self.blackhole,
        )
        self.adaptive = AdaptiveEngine(config.adaptive)
        self.correlator = AttackCorrelator(
            config.correlator, self.state,
            reputation=self.reputation,
            router=self.router,
            dry_run=config.dry_run,
        )
        self.eventstore = EventStore(config.eventstore)
        self.metrics = MetricsServer(config.metrics)
        self.alerts = AlertEngine(config.raw.get("alerts", {}))
        self.registry = RegistryClient(config.raw.get("registry", {}), daemon=self)
        self._shutdown = threading.Event()

        # Restore persisted state (reputation scores, blackhole entries)
        state_file = config.general.get("state_file", "")
        if state_file:
            self.state.load(
                state_file,
                reputation=self.reputation,
                blackhole=self.blackhole,
            )
        self._ready = threading.Event()   # Set once control socket is listening
        self._rns_instance = None
        self._i2p_interfaces: list = []
        self._i2p_peers: list[dict] = []    # [{name, b32}] for peer (non-server) interfaces
        self._tcp_peers: list[dict] = []    # [{name, host, port}] for TCP client interfaces
        self._tcp_servers: list[dict] = []  # [{name, listen_ip, port}] for TCP server interfaces
        self._ctl_thread: threading.Thread | None = None

    def init(self, install_signals: bool = True):
        """Initialize Reticulum, hook, and subsystems.

        MUST be called from the main thread (Reticulum registers signal
        handlers internally).  After this returns the daemon is ready for
        RPC connections but the maintenance loop is not yet running —
        call :meth:`run` for that.

        Args:
            install_signals: Register SIGTERM/SIGINT/SIGHUP handlers.
                Set False when running under a TUI that owns signal handling.
        """
        log.info("Rathole v1.0.0 — transport node security suite")
        log.info("Dry-run mode: %s", self.config.dry_run)

        # Suppress known-harmless asyncio warning from i2plib proxy_data()
        # when I2P tunnels drop/reconnect or during shutdown.
        class _I2PTaskWarningFilter(logging.Filter):
            def filter(self, record):
                msg = record.getMessage()
                if "was destroyed but it is pending" in msg and "proxy_data" in msg:
                    return False
                return True

        logging.getLogger("asyncio").addFilter(_I2PTaskWarningFilter())

        # Initialize Reticulum (registers signals — needs main thread)
        self._init_reticulum()

        # Populate _i2p_peers from interfaces already loaded by rnsd/RNS on startup.
        # When rathole restarts (or connects to a running rnsd), I2P peer interfaces
        # that were persisted in the RNS config are already live in Transport.interfaces
        # but _i2p_peers starts empty.  Scan and backfill so the TUI shows them.
        self._sync_i2p_peers_from_transport()

        # Same backfill for TCP client interfaces persisted in the RNS config.
        self._sync_tcp_peers_from_transport()

        # Backfill TCP server interfaces persisted in the RNS config.
        self._sync_tcp_servers_from_transport()

        # Install the Transport hook
        install_hook(self.router)

        # Register signal handlers (skip when TUI manages signals)
        if install_signals:
            signal.signal(signal.SIGTERM, self._handle_signal)
            signal.signal(signal.SIGINT, self._handle_signal)
            if hasattr(signal, "SIGHUP"):
                signal.signal(signal.SIGHUP, self._handle_sighup)

        # Attach blackhole manager to live RNS Transport for sync
        try:
            import RNS
            self.blackhole.attach_transport(RNS.Transport)
        except Exception as e:
            log.warning("Could not attach blackhole to RNS Transport: %s", e)

        # ── Wire up subsystems ────────────────────────────────────
        if self.alerts.enabled:
            self.event_bus.subscribe(self.alerts.evaluate)
            log.info("Alert engine subscribed to event bus")

        if self.eventstore.enabled:
            self.event_bus.subscribe(self.eventstore.store)
            log.info("Event store subscribed to event bus")

        if self.metrics.enabled:
            self.metrics.start()

        # Log startup summary
        mode = "DRY-RUN" if self.config.dry_run else "ACTIVE"
        adaptive_status = ""
        if self.config.adaptive.get("enabled"):
            hours = self.config.adaptive.get("learning_hours", 24)
            adaptive_status = f" (adaptive learning: {hours}h)"
        sock_path = self.config.general.get("control_socket", "")
        log.info("Mode: %s%s", mode, adaptive_status)
        if sock_path:
            log.info("Control socket: %s", sock_path)
        log.info("Rathole running — filtering all packet types")

        # Start the control socket listener in a background thread
        self._start_control_socket()

        # Registry: init gateway destination and first announce (best-effort)
        if self.registry.enabled and self.registry._publish:
            try:
                self.registry.init_gateway_destination()
                self.registry.register()
            except Exception as e:
                log.warning("Registry initial announce failed: %s", e)

        # Signal that the daemon is ready for RPC connections
        self._ready.set()

    def run(self):
        """Run the maintenance loop (blocking, can run in any thread)."""
        self._maintenance_loop()

    def start(self, install_signals: bool = True):
        """Convenience: init + run in one call (must be on main thread)."""
        self.init(install_signals=install_signals)
        self.run()

    def stop(self):
        """Graceful shutdown."""
        log.info("Rathole shutting down")
        self._shutdown.set()
        uninstall_hook()

        # Stop announcing (entry will expire on the registry after TTL)
        if self.registry.enabled and self.registry._published:
            try:
                self.registry.deregister()
            except Exception as e:
                log.debug("Registry deregister on shutdown: %s", e)

        # Stop metrics server
        if self.metrics.enabled:
            self.metrics.stop()

        # Close event store
        if self.eventstore.enabled:
            self.eventstore.close()

        # Final state save
        state_file = self.config.general.get("state_file", "")
        if state_file:
            try:
                self.state.save(
                    state_file,
                    reputation=self.reputation,
                    blackhole=self.blackhole,
                )
                log.info("Final state saved to %s", state_file)
            except OSError as e:
                log.warning("Failed to save final state: %s", e)

        # Wait for control socket thread to exit (checks _shutdown flag)
        if self._ctl_thread is not None:
            self._ctl_thread.join(timeout=5.0)
            self._ctl_thread = None

        # Detach tracked I2P interfaces explicitly before global teardown
        for iface in self._i2p_interfaces:
            try:
                if hasattr(iface, "detach"):
                    iface.detach()
            except Exception:
                pass
        self._i2p_interfaces.clear()

        log.info("Rathole stopped")

        # Tear down the Reticulum singleton so a new instance can be
        # created if the process is re-used (e.g. reset → setup → start).
        # Done after final log message since teardown suppresses RNS logging
        # to avoid spurious "Bad file descriptor" errors during interface
        # detach.
        self._teardown_reticulum()

    @staticmethod
    def _teardown_reticulum():
        """Reset the RNS.Reticulum singleton so it can be re-initialized.

        Reticulum uses a class-level ``__instance`` guard that raises
        ``OSError`` on a second ``RNS.Reticulum()`` call in the same
        process.  After a graceful shutdown we need to clear that so the
        daemon can be re-started without restarting the whole process.

        Also clears Transport.destinations to prevent 'already registered
        destination' errors when re-initializing with transport enabled.

        RNS logging is temporarily suppressed during teardown to avoid
        spurious "Bad file descriptor" errors from interface threads that
        are shutting down.
        """
        try:
            import RNS

            # Suppress RNS log noise during teardown — interface threads
            # may log "Bad file descriptor" errors as sockets close.
            rns_logger = logging.getLogger("RNS")
            prev_level = rns_logger.level
            rns_logger.setLevel(logging.CRITICAL)

            # Shut down the transport layer
            if hasattr(RNS.Transport, "exit_handler"):
                try:
                    RNS.Transport.exit_handler()
                except Exception:
                    pass

            # Clear destination registries to avoid 'already registered' on re-init
            for attr in ("destinations", "control_destinations", "mgmt_destinations"):
                if hasattr(RNS.Transport, attr):
                    try:
                        getattr(RNS.Transport, attr).clear()
                    except Exception:
                        pass

            # Tear down interfaces (I2P interfaces have async tunnel
            # teardown that needs a brief settle after detach)
            has_i2p = False
            if hasattr(RNS.Transport, "interfaces"):
                for iface in list(RNS.Transport.interfaces):
                    try:
                        if hasattr(iface, "detach"):
                            if "I2P" in type(iface).__name__:
                                has_i2p = True
                            iface.detach()
                    except Exception:
                        pass
                if has_i2p:
                    time.sleep(2.0)
                try:
                    RNS.Transport.interfaces.clear()
                except Exception:
                    pass

            # Clear the singleton guard
            if hasattr(RNS.Reticulum, "_Reticulum__instance"):
                RNS.Reticulum._Reticulum__instance = None
            elif hasattr(RNS.Reticulum, "__instance"):
                RNS.Reticulum.__instance = None

            # Restore RNS log level, then let daemon threads wind down
            # before the interpreter finalizes them.
            rns_logger.setLevel(prev_level)
            time.sleep(0.5)

        except ImportError:
            pass
        except Exception:
            pass

    @staticmethod
    def _patch_darwin_autointerface():
        """On macOS, add utun* tunnel interfaces to AutoInterface ignore list.

        macOS creates utun0-utunN for VPN, iCloud Private Relay, and network
        extensions.  These are point-to-point tunnel interfaces that
        intermittently fail multicast (Errno 55 "No buffer space available"),
        flooding the log with carrier-loss warnings.

        We patch the class-level DARWIN_IGNORE_IFS before RNS.Reticulum()
        initialises AutoInterface, so the tunnels are silently skipped.
        """
        import platform
        if platform.system() != "Darwin":
            return

        try:
            import socket
            from RNS.Interfaces.AutoInterface import AutoInterface

            if not hasattr(socket, "if_nameindex"):
                return

            utun_ifs = [
                name for _, name in socket.if_nameindex()
                if name.startswith("utun")
            ]
            if not utun_ifs:
                return

            current = list(AutoInterface.DARWIN_IGNORE_IFS)
            added = [ifn for ifn in utun_ifs if ifn not in current]
            if added:
                AutoInterface.DARWIN_IGNORE_IFS = current + added
                log.info(
                    "macOS: ignoring tunnel interfaces for AutoInterface: %s",
                    ", ".join(added),
                )
        except Exception:
            pass  # Fail-open — don't break startup over this

    def _init_reticulum(self):
        """Start a Reticulum instance and ensure transport is enabled."""
        try:
            import RNS
        except ImportError:
            log.error(
                "Reticulum (rns) not installed. "
                "Install with: pip install rns"
            )
            raise SystemExit(1)

        # Patch out macOS tunnel interfaces before AutoInterface discovers them
        self._patch_darwin_autointerface()

        rns_config_path = self.config.general.get("reticulum_config_path", "") or None

        # Enable transport in the config file BEFORE creating the instance.
        # This avoids a teardown/re-init cycle that loses TCP interfaces.
        self._ensure_transport_enabled(rns_config_path)

        try:
            self._rns_instance = RNS.Reticulum(configdir=rns_config_path)
        except OSError as e:
            if "reinitialise" in str(e).lower() or "already" in str(e).lower():
                log.warning(
                    "RNS singleton already exists — clearing and retrying"
                )
                self._teardown_reticulum()
                self._rns_instance = RNS.Reticulum(configdir=rns_config_path)
            else:
                raise
        log.info(
            "Reticulum initialized (config: %s)",
            rns_config_path or "default",
        )

        # Verify transport is actually on.
        # Skip check for shared-instance clients — transport runs on the
        # shared daemon (rnsd), not the client, so it's always False here.
        is_client = getattr(self._rns_instance, "is_connected_to_shared_instance", False)
        if not is_client and not RNS.Reticulum.transport_enabled():
            # First-run case: config file didn't exist before RNS created it.
            # Fix the config now so transport is active on next start.
            self._ensure_transport_enabled(rns_config_path)

            # Try to hot-enable transport on the live instance without teardown
            try:
                if hasattr(RNS.Transport, "start"):
                    # Set the private flag that transport_enabled() checks
                    RNS.Reticulum._Reticulum__transport_enabled = True
                    RNS.Transport.start(self._rns_instance)
                    log.info("Transport hot-enabled on running instance")
            except Exception as e:
                log.debug("Could not hot-enable transport: %s", e)

            if not RNS.Reticulum.transport_enabled():
                log.warning(
                    "Transport is NOT enabled. Config has been fixed — "
                    "transport will be active on next restart."
                )

        # Log transport identity
        if hasattr(RNS.Transport, "identity") and RNS.Transport.identity:
            log.info("Transport identity: %s", RNS.Transport.identity.hexhash)

        # Log active interfaces
        iface_names = []
        if hasattr(RNS.Transport, "interfaces"):
            for iface in RNS.Transport.interfaces:
                name = getattr(iface, "name", None) or str(type(iface).__name__)
                iface_names.append(name)
        log.info("Interfaces active: %d%s",
                 len(iface_names),
                 f" ({', '.join(iface_names)})" if iface_names else "")

        # ── Log LoRa interface details at startup ─────────────────────
        # Prints mode, frequency, SF, BW, and online status for every
        # RNode/LoRa interface so it's immediately visible in docker logs
        # whether the radio is configured correctly.
        if hasattr(RNS.Transport, "interfaces"):
            for iface in RNS.Transport.interfaces:
                itype = type(iface).__name__
                if "RNode" not in itype and "LoRa" not in itype:
                    continue
                iname   = getattr(iface, "name", itype)
                online  = getattr(iface, "online", None)
                mode_v  = getattr(iface, "mode", None)
                freq    = getattr(iface, "frequency", None)
                bw      = getattr(iface, "bandwidth", None)
                sf      = getattr(iface, "sf", None)
                cr      = getattr(iface, "cr", None)
                txpwr   = getattr(iface, "txpower", None)
                bitrate = getattr(iface, "bitrate", None)
                _MODE_NAMES = {1: "full", 2: "point_to_point",
                               3: "access_point", 4: "roaming",
                               5: "boundary", 6: "gateway"}
                mode_str = _MODE_NAMES.get(mode_v, f"mode_{mode_v}") if mode_v is not None else "?"
                log.info(
                    "LoRa startup: [%s] online=%s mode=%s(%s) "
                    "freq=%s Hz SF%s BW=%s Hz txpwr=%s dBm bitrate=%s bps",
                    iname, online, mode_str, mode_v,
                    freq, sf, bw, txpwr, bitrate,
                )
                # Log mode for visibility (full mode is intentional for testing)
                if mode_v == 0:
                    log.info(
                        "LoRa [%s] is in FULL mode (peer transport node).",
                        iname,
                    )

    def _ensure_transport_enabled(self, rns_config_path):
        """Ensure the RNS config is correct before ``RNS.Reticulum()`` is called.

        Two settings are enforced:

        ``enable_transport = Yes``
            Rathole is a transport node — it must route announces and serve
            path requests.  Without this, RNS starts in client mode and the
            filter hook has nothing to intercept.

        ``share_instance = Yes``
            Rathole runs alongside rnsd (the shared Reticulum daemon) and
            connects to it as a shared-instance client.  With
            ``share_instance = Yes`` (the RNS default) the first
            ``RNS.Reticulum()`` call in the process becomes the
            shared-instance owner; subsequent calls (including rathole's own)
            attach as clients.  This is the correct mode when rnsd already
            owns the RNodeInterface — rathole does not need to open the serial
            port directly.

        Note: RNodeInterface mode is NOT enforced here.  The mode is
        preserved as-is from the config file.  For I2P→LoRa bridging the
        LoRa interface must be in ``full`` or ``gateway`` mode — ``access_point``
        only re-propagates FROM LoRa TO other interfaces, not the reverse.
        The ``_add_lora_interface()`` method defaults to ``full`` mode for
        this reason.
        """
        if rns_config_path:
            config_dir = Path(rns_config_path)
        else:
            config_dir = _default_rns_dir()

        config_file = config_dir / "config"
        if not config_file.exists():
            # RNS will create defaults on first run — we can't fix it
            # before init, but transport_enabled() check after will catch it.
            return

        try:
            from configobj import ConfigObj
            cfg = ConfigObj(str(config_file))
            rns_section = cfg.get("reticulum", {})

            changed = False

            # Enforce enable_transport = Yes
            transport_val = str(rns_section.get("enable_transport", "No")).lower()
            if transport_val not in ("yes", "true", "1"):
                if "reticulum" not in cfg:
                    cfg["reticulum"] = {}
                cfg["reticulum"]["enable_transport"] = "Yes"
                changed = True
                log.info("Transport auto-enabled in %s", config_file)

            # Enforce share_instance = Yes
            # Rathole connects to the shared rnsd instance; it does not need
            # to own the serial port directly.
            share_val = str(rns_section.get("share_instance", "Yes")).lower()
            if share_val not in ("yes", "true", "1"):
                if "reticulum" not in cfg:
                    cfg["reticulum"] = {}
                cfg["reticulum"]["share_instance"] = "Yes"
                changed = True
                log.info("share_instance set to Yes in %s (rathole uses shared rnsd instance)",
                         config_file)

            # NOTE: RNodeInterface mode enforcement intentionally removed.
            # Mode is preserved as-is from the config file to allow testing
            # with mode = full (peer transport node mode).

            if changed:
                cfg.write()

        except ImportError:
            # configobj not installed — text-based fallback
            try:
                import re as _re
                text = config_file.read_text()
                lines = text.splitlines()
                changed = False

                # Helper: set or insert a key in the [reticulum] section
                def _set_key(lines, key, value):
                    # Replace existing key
                    for i, line in enumerate(lines):
                        stripped = line.strip().lower()
                        if stripped.startswith(key.lower()) and "=" in stripped:
                            lines[i] = f"  {key} = {value}"
                            return lines, True
                    # Insert after [reticulum] header
                    for i, line in enumerate(lines):
                        if line.strip().lower() == "[reticulum]":
                            lines.insert(i + 1, f"  {key} = {value}")
                            return lines, True
                    return lines, False

                # Check enable_transport
                transport_ok = False
                for line in lines:
                    stripped = line.strip().lower()
                    if stripped.startswith("enable_transport") and "=" in stripped:
                        val = stripped.split("=", 1)[1].strip()
                        if val in ("yes", "true", "1"):
                            transport_ok = True
                        break
                if not transport_ok:
                    lines, ok = _set_key(lines, "enable_transport", "Yes")
                    if ok:
                        changed = True
                        log.info("Transport auto-enabled in %s", config_file)

                # Check share_instance
                share_ok = False
                for line in lines:
                    stripped = line.strip().lower()
                    if stripped.startswith("share_instance") and "=" in stripped:
                        val = stripped.split("=", 1)[1].strip()
                        if val in ("yes", "true", "1"):
                            share_ok = True
                        break
                if not share_ok:
                    lines, ok = _set_key(lines, "share_instance", "Yes")
                    if ok:
                        changed = True
                        log.info("share_instance set to Yes in %s", config_file)

                # NOTE: RNodeInterface mode enforcement intentionally removed.
                # Mode is preserved as-is from the config file.

                if changed:
                    config_file.write_text("\n".join(lines) + "\n")

            except Exception as e:
                log.warning("Could not update RNS config: %s", e)
        except Exception as e:
            log.warning("Could not update RNS config: %s", e)

    def _maintenance_loop(self):
        """
        Periodic maintenance: state persistence, decay, pruning.
        Runs until shutdown signal.
        """
        persist_interval = self.config.general.get("state_persist_interval", 300)
        state_file = self.config.general.get("state_file", "")
        churn_cfg = self.config.filter_cfg("churn")
        decay_interval = churn_cfg.get("decay_interval", 300)
        decay_factor = churn_cfg.get("decay_factor", 0.5)

        last_persist = time.monotonic()
        last_decay = time.monotonic()
        last_prune = time.monotonic()
        last_correlator = time.monotonic()
        last_link_decay = time.monotonic()
        last_metrics = time.monotonic()
        last_auto_blackhole = time.monotonic()
        last_peers_flush = time.monotonic()
        last_registry_heartbeat = time.monotonic()
        last_registry_discover = time.monotonic()
        last_reputation_decay = time.monotonic()
        correlator_interval = self.config.correlator.get("interval", 30)

        while not self._shutdown.is_set():
            now = time.monotonic()

            # Persist state
            if state_file and persist_interval > 0:
                if now - last_persist >= persist_interval:
                    try:
                        self.state.save(
                            state_file,
                            reputation=self.reputation,
                            blackhole=self.blackhole,
                        )
                    except OSError as e:
                        log.warning("Failed to persist state: %s", e)
                    last_persist = now

            # Decay churn penalties
            if now - last_decay >= decay_interval:
                self.state.apply_decay(decay_factor, decay_interval)
                last_decay = now

            # Prune stale destination entries (hourly)
            if now - last_prune >= 3600:
                self.state.prune_stale()
                self.reputation.prune_stale()
                last_prune = now

            # Run attack correlator (default every 30s)
            if self.correlator.enabled and now - last_correlator >= correlator_interval:
                try:
                    alerts = self.correlator.run()
                    for alert in alerts:
                        self._emit_correlator_event(alert)
                except Exception as e:
                    log.error("Correlator error: %s", e)
                # Reset windowed counters after each correlator interval
                self.state.reset_interface_windows()
                last_correlator = now

            # Update rate computations each cycle
            self.state.update_rates()

            # Feed adaptive engine with per-interface metrics
            if self.adaptive.enabled:
                for iface in self.state.interface_summary():
                    name = iface["interface"]
                    self.adaptive.record(name, "packet_rate", iface["packets"])
                    self.adaptive.record(name, "announce_rate", iface["announces"])
                    self.adaptive.record(name, "byte_rate", iface["bytes"])

            # Flush peers timeline (every 60s)
            if now - last_peers_flush >= 60:
                self.state.flush_peers_timeline()
                last_peers_flush = now

            # Decay link/resource counters (every 60s)
            if now - last_link_decay >= 60:
                self.state.decay_link_resources()
                last_link_decay = now

            # Auto-blackhole low-reputation identities (every 60s)
            if now - last_auto_blackhole >= 60:
                self._check_auto_blackhole()
                self.blackhole.periodic_sync()
                last_auto_blackhole = now

            # Decay reputation scores toward neutral (every 5 min)
            if now - last_reputation_decay >= 300:
                self.reputation.decay_all()
                last_reputation_decay = now

            # Update Prometheus metrics (every 30s)
            if self.metrics.enabled and now - last_metrics >= 30:
                try:
                    self.metrics.update_from_state(
                        self.state,
                        reputation=self.reputation,
                        blackhole=self.blackhole,
                        config=self.config,
                    )
                except Exception as e:
                    log.error("Metrics update error: %s", e)
                last_metrics = now

            # Prune event store (checks internal interval)
            if self.eventstore.enabled:
                self.eventstore.prune()

            # Registry announce (heartbeat)
            # Use a shorter interval (30s) until B32 is available so
            # I2P nodes re-announce promptly once the tunnel is up.
            if self.registry.enabled and self.registry._publish:
                from .i2p import get_i2p_b32_from_transport
                b32_ready = get_i2p_b32_from_transport() is not None
                hb_interval = self.registry._announce_interval if b32_ready else 30
                if now - last_registry_heartbeat >= hb_interval:
                    try:
                        self.registry.heartbeat()
                    except Exception as e:
                        log.warning("Registry heartbeat failed: %s", e)
                    last_registry_heartbeat = now

            # Registry discover + auto-connect
            if self.registry.enabled and self.registry._discover:
                disc_interval = self.registry._discover_interval
                if now - last_registry_discover >= disc_interval:
                    try:
                        entries = self.registry.discover()
                        if self.registry._auto_connect and not self.config.dry_run:
                            self.registry.auto_connect(entries)
                    except Exception as e:
                        log.warning("Registry discover failed: %s", e)
                    last_registry_discover = now

            # Sleep in short intervals so we can respond to shutdown quickly
            self._shutdown.wait(timeout=5.0)

    def _start_control_socket(self):
        """Start the control socket listener for rat commands."""
        sock_path = self.config.general.get("control_socket", "")
        if not sock_path:
            return

        from .rpc import _is_tcp_address
        if _is_tcp_address(sock_path):
            target = self._control_socket_loop_tcp
        else:
            target = self._control_socket_loop_unix

        t = threading.Thread(
            target=target,
            args=(sock_path,),
            daemon=True,
            name="rat",
        )
        t.start()
        self._ctl_thread = t

    def _control_socket_loop_unix(self, sock_path: str):
        """Handle control commands over a Unix domain socket."""
        import socket
        import json

        path = Path(sock_path)
        if path.exists():
            path.unlink()

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            log.warning("Cannot create control socket directory: %s", path.parent)
            return

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.settimeout(2.0)
        try:
            srv.bind(str(path))
            import os
            os.chmod(str(path), 0o700)
            srv.listen(5)
            log.info("Control socket listening on %s", sock_path)
        except OSError as e:
            log.warning("Cannot bind control socket: %s", e)
            return

        while not self._shutdown.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                data = conn.recv(4096).decode().strip()
                response = self._handle_ctl_command(data)
                conn.sendall(json.dumps(response).encode() + b"\n")
            except BrokenPipeError:
                pass  # Client closed before reading response — harmless
            except Exception as e:
                log.error("Control socket error: %s", e)
            finally:
                conn.close()

        srv.close()
        if path.exists():
            path.unlink()

    def _control_socket_loop_tcp(self, sock_path: str):
        """Handle control commands over a TCP localhost socket."""
        import socket
        import json

        try:
            host, port_str = sock_path.rsplit(":", 1)
            port = int(port_str)
        except (ValueError, AttributeError):
            log.warning("Invalid TCP control socket address: %s", sock_path)
            return

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(2.0)
        try:
            srv.bind((host, port))
            srv.listen(5)
            log.info("Control socket listening on %s", sock_path)
        except OSError as e:
            log.warning("Cannot bind control socket: %s", e)
            return

        while not self._shutdown.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                data = conn.recv(4096).decode().strip()
                response = self._handle_ctl_command(data)
                conn.sendall(json.dumps(response).encode() + b"\n")
            except BrokenPipeError:
                pass  # Client closed before reading response — harmless
            except Exception as e:
                log.error("Control socket error: %s", e)
            finally:
                conn.close()

        srv.close()

    def _enrich_peers(self, peers: list[dict]) -> list[dict]:
        """Merge reputation data into peer summary entries.

        Blackholed peers are excluded — they appear in the Blackhole tab instead.
        """
        result = []
        for p in peers:
            peer_hash = p["peer"]
            if self.blackhole.is_blackholed(peer_hash):
                continue
            rep = self.reputation.get(peer_hash)
            p["reputation"] = round(rep.effective_score, 3)
            p["category"] = rep.category.name
            p["drops"] = rep.total_drops
            p["pinned"] = rep.pinned
            result.append(p)
        return result

    def _emit_correlator_event(self, alert):
        """Convert a CorrelationAlert to a SecurityEvent and emit to event bus."""
        event_info = self._CORRELATOR_EVENT_MAP.get(alert.pattern.name)
        if event_info is None:
            return

        event_type, severity = event_info
        self.event_bus.emit(SecurityEvent(
            event_type=event_type,
            severity=severity,
            source="correlator",
            interface_name=alert.interface_name,
            description=alert.description,
            details={
                "pattern": alert.pattern.name,
                "evidence": alert.evidence,
                "response_executed": alert.response_executed,
            },
        ))

    def handle_command(self, cmd: str, args: dict | None = None) -> dict:
        """Public API: dispatch a command and return the response dict.

        This is the preferred interface when the caller is in the same
        process (e.g. the unified TUI).  No serialization overhead, no
        socket, no chance of ``errno 57``.
        """
        return self._dispatch_command(cmd, args or {})

    def _handle_ctl_command(self, raw: str) -> dict:
        """Process a control command from the Unix socket.

        Commands are JSON-RPC-style: {"cmd": "name", "args": {...}}
        Or plain strings for backward compatibility (e.g., "status").
        """
        import json as _json

        # Parse JSON or treat as simple string command
        try:
            msg = _json.loads(raw)
            cmd = msg.get("cmd", "")
            args = msg.get("args", {})
        except (_json.JSONDecodeError, AttributeError):
            cmd = raw.strip()
            args = {}

        return self._dispatch_command(cmd, args)

    @staticmethod
    def _validate_identity(h: str) -> str | None:
        """Validate an identity hash string. Returns error message or None."""
        if not h or not isinstance(h, str):
            return "identity must be a non-empty string"
        h = h.strip()
        if not all(c in "0123456789abcdefABCDEF" for c in h):
            return "identity must be a hex string"
        if len(h) < 16:
            return "identity hash too short (min 16 hex chars)"
        return None

    def _dispatch_command(self, cmd: str, args: dict) -> dict:
        """Internal command dispatcher shared by socket and direct paths."""
        try:
            return self._dispatch_command_inner(cmd, args)
        except Exception as e:
            log.error("RPC dispatch error for cmd=%s: %s", cmd, e)
            return {"ok": False, "error": f"Internal error: {e}"}

    def _dispatch_command_inner(self, cmd: str, args: dict) -> dict:
        """Actual command dispatch logic."""

        if cmd == "status":
            stats = self.state.stats
            stats["dry_run"] = self.config.dry_run
            stats["node_mode"] = self.config.node_mode
            stats["reputation_distribution"] = self.reputation.reputation_distribution()
            stats["filter_effectiveness"] = dict(
                list(self.state.filter_effectiveness().items())[:5]
            )
            from .i2p import get_i2p_b32_from_transport, has_i2p_interface
            stats["i2p_b32"] = get_i2p_b32_from_transport()
            stats["i2p_pending"] = has_i2p_interface() and not stats["i2p_b32"]
            # Enrich i2p_peers with live tunnel status by scanning Transport.interfaces.
            # The interface name in RNS is "I2P Peer <b32[:8]> to <full_b32>" while
            # we store only the short form "I2P Peer <b32[:8]>".  Match by prefix.
            # Three states:
            #   connected=True  — interface present and online=True  (Status: Up)
            #   connected=False, present=True  — interface present but online=False
            #                                    (Status: Down, tunnel establishing
            #                                     or brief post-restart check window)
            #   connected=False, present=False — interface not in transport at all
            #                                    (genuinely connecting / not yet added)
            try:
                import RNS as _RNS
                _live_online: set[str] = set()   # online=True
                _live_down: set[str] = set()     # present but online=False
                for _iface in _RNS.Transport.interfaces:
                    _iname = getattr(_iface, "name", "") or ""
                    if "I2P" in type(_iface).__name__ and not getattr(_iface, "connectable", False):
                        if getattr(_iface, "online", True):
                            _live_online.add(_iname)
                        else:
                            _live_down.add(_iname)
            except Exception:
                _live_online = set()
                _live_down = set()

            _enriched_peers = []
            for _p in self._i2p_peers:
                _pname = _p.get("name", "")
                _is_online = any(
                    _ln == _pname or _ln.startswith(_pname + " ")
                    for _ln in _live_online
                )
                _is_down = any(
                    _ln == _pname or _ln.startswith(_pname + " ")
                    for _ln in _live_down
                )
                # Clear "new" flag once the peer becomes connected for the
                # first time — after that, Down state shows "Checking…"
                # rather than "Connecting" (tunnel was established before).
                if _is_online and _p.get("new"):
                    _p["new"] = False
                _enriched_peers.append({
                    **_p,
                    "connected": _is_online,
                    "present": _is_online or _is_down,
                })
            stats["i2p_peers"] = _enriched_peers

            # Enrich tcp_peers with live connection status by scanning Transport.interfaces.
            # TCPClientInterface name is "TCP <host>:<port>" — exact match.
            # Three states mirror the I2P pattern:
            #   connected=True  — interface present and online=True
            #   connected=False, present=True  — interface present but online=False
            #                                    (reconnecting after drop)
            #   connected=False, present=False — not in transport (first-time connect)
            try:
                import RNS as _RNS
                _tcp_live_online: set[str] = set()
                _tcp_live_down: set[str] = set()
                for _iface in _RNS.Transport.interfaces:
                    _iname = getattr(_iface, "name", "") or ""
                    _itype = type(_iface).__name__
                    if "TCPClient" in _itype:
                        if getattr(_iface, "online", True):
                            _tcp_live_online.add(_iname)
                        else:
                            _tcp_live_down.add(_iname)
            except Exception:
                _tcp_live_online = set()
                _tcp_live_down = set()

            _enriched_tcp = []
            for _tp in self._tcp_peers:
                _tname = _tp.get("name", "")
                _t_online = _tname in _tcp_live_online
                _t_down   = _tname in _tcp_live_down
                if _t_online and _tp.get("new"):
                    _tp["new"] = False
                _enriched_tcp.append({
                    **_tp,
                    "connected": _t_online,
                    "present": _t_online or _t_down,
                })
            stats["tcp_peers"] = _enriched_tcp

            # Enrich tcp_servers with live listening status.
            # TCPServerInterface name is "TCP Server <ip>:<port>" — exact match.
            # Two states:
            #   listening=True  — interface present and online=True  (bound and accepting)
            #   listening=False — interface present but online=False (binding / activating)
            try:
                import RNS as _RNS
                _srv_live_online: set[str] = set()
                _srv_live_down: set[str] = set()
                for _iface in _RNS.Transport.interfaces:
                    _iname = getattr(_iface, "name", "") or ""
                    _itype = type(_iface).__name__
                    if "TCPServer" in _itype:
                        if getattr(_iface, "online", True):
                            _srv_live_online.add(_iname)
                        else:
                            _srv_live_down.add(_iname)
            except Exception:
                _srv_live_online = set()
                _srv_live_down = set()

            _enriched_servers = []
            for _sv in self._tcp_servers:
                _svname = _sv.get("name", "")
                _sv_online = _svname in _srv_live_online
                _sv_down   = _svname in _srv_live_down
                if _sv_online and _sv.get("new"):
                    _sv["new"] = False
                _enriched_servers.append({
                    **_sv,
                    "listening": _sv_online,
                    "present": _sv_online or _sv_down,
                })
            stats["tcp_servers"] = _enriched_servers

            from .lora import detect_lora_interfaces
            stats["lora_interfaces"] = detect_lora_interfaces()
            peers = self._enrich_peers(self.state.peer_summary())
            return {
                "ok": True,
                "stats": stats,
                "peers": peers,
                "interfaces": self.state.interface_summary(),
            }
        elif cmd == "peers":
            return {"ok": True, "peers": self._enrich_peers(self.state.peer_summary())}
        elif cmd == "interfaces":
            return {"ok": True, "interfaces": self.state.interface_summary()}
        elif cmd == "events":
            limit = args.get("limit", 50)
            return {
                "ok": True,
                "events": [e.to_dict() for e in self.event_bus.recent(limit)],
                "stats": self.event_bus.stats(),
            }
        elif cmd == "reputation":
            action = args.get("action", "")
            identity = args.get("identity", "")
            if action == "pin":
                if not identity:
                    return {"ok": False, "error": "identity required"}
                err = self._validate_identity(identity)
                if err:
                    return {"ok": False, "error": err}
                score = float(args.get("score", 1.0))
                self.reputation.pin(identity, score)
                return {"ok": True, "pinned": True, "score": score}
            elif action == "unpin":
                if not identity:
                    return {"ok": False, "error": "identity required"}
                err = self._validate_identity(identity)
                if err:
                    return {"ok": False, "error": err}
                self.reputation.unpin(identity)
                return {"ok": True, "pinned": False}
            elif identity:
                rep = self.reputation.get(identity)
                return {
                    "ok": True,
                    "identity": identity,
                    "score": rep.effective_score,
                    "category": rep.category.name,
                    "accepts": rep.total_accepts,
                    "drops": rep.total_drops,
                    "pinned": rep.pinned,
                }
            return {
                "ok": True,
                "identities": self.reputation.summary(),
                "category_transitions": self.reputation.category_transitions(),
                "distribution": self.reputation.reputation_distribution(),
                "auto_blackhole_count": self.reputation._auto_blackhole_count,
            }
        elif cmd == "blackhole":
            subcmd = args.get("action", "list")
            if subcmd == "list":
                return {"ok": True, "blackholed": self.blackhole.list_all()}
            elif subcmd == "add":
                identity = args.get("identity", "")
                reason = args.get("reason", "manual")
                if not identity:
                    return {"ok": False, "error": "identity required"}
                err = self._validate_identity(identity)
                if err:
                    return {"ok": False, "error": err}
                added = self.blackhole.add(identity, reason=reason)
                if added:
                    self.event_bus.emit(SecurityEvent(
                        event_type=EventType.IDENTITY_BLACKHOLED,
                        severity=EventSeverity.ALERT,
                        source="manual",
                        identity_hash=identity,
                        description=f"Manually blackholed {identity[:16]}: {reason}",
                    ))
                return {"ok": True, "added": added}
            elif subcmd == "remove":
                identity = args.get("identity", "")
                if not identity:
                    return {"ok": False, "error": "identity required"}
                err = self._validate_identity(identity)
                if err:
                    return {"ok": False, "error": err}
                removed = self.blackhole.remove(identity)
                if removed:
                    self.event_bus.emit(SecurityEvent(
                        event_type=EventType.IDENTITY_UNBLACKHOLED,
                        severity=EventSeverity.NOTICE,
                        source="manual",
                        identity_hash=identity,
                        description=f"Removed {identity[:16]} from blackhole",
                    ))
                return {"ok": True, "removed": removed}
            return {"ok": False, "error": f"Unknown blackhole action: {subcmd}"}
        elif cmd == "adaptive":
            return {"ok": True, "adaptive": self.adaptive.summary()}
        elif cmd == "correlator":
            return {"ok": True, "correlator": self.correlator.summary()}
        elif cmd == "alerts":
            return {"ok": True, "alerts": self.alerts.summary()}
        elif cmd == "config":
            subcmd = args.get("action", "show")
            if subcmd == "show":
                return {"ok": True, "config": self.config.raw}
            elif subcmd == "set":
                # Live config override — limited to filter toggles
                section = args.get("section", "")
                key = args.get("key", "")
                value = args.get("value")
                if section and key and value is not None:
                    if section in self.config.raw:
                        self.config.raw[section][key] = value
                    elif section in self.config.raw.get("filters", {}):
                        self.config.raw["filters"][section][key] = value
                    else:
                        return {"ok": False, "error": f"unknown config section: {section}"}
                    from .config import _validate
                    _validate(self.config.raw)
                    self._propagate_config()
                    save_config(self.config)
                    return {"ok": True}
                return {"ok": False, "error": "section, key, and value required"}
            return {"ok": False, "error": f"Unknown config action: {subcmd}"}
        elif cmd == "dry-run":
            mode = args.get("mode", "")
            if mode == "on":
                self.config.raw["general"]["dry_run"] = True
                self._propagate_config()
                save_config(self.config)
                return {"ok": True, "dry_run": True}
            elif mode == "off":
                self.config.raw["general"]["dry_run"] = False
                self._propagate_config()
                save_config(self.config)
                return {"ok": True, "dry_run": False}
            return {"ok": True, "dry_run": self.config.dry_run}
        elif cmd == "reload":
            self.config = reload_config(self.config)
            self._propagate_config()
            return {"ok": True}
        elif cmd == "presets":
            subcmd = args.get("action", "list")
            if subcmd == "list":
                from .presets import list_presets, preset_diff
                mode = args.get("mode", None) or self.config.node_mode
                presets = list_presets(mode)
                for p in presets:
                    p["diff"] = preset_diff(p["name"])
                return {"ok": True, "presets": presets, "node_mode": self.config.node_mode}
            elif subcmd == "apply":
                from .presets import apply_preset
                name = args.get("name", "")
                try:
                    merged = apply_preset(name)
                except ValueError as e:
                    return {"ok": False, "error": str(e)}
                self.config.raw = merged
                self._propagate_config()
                save_config(self.config)
                return {"ok": True}
            elif subcmd == "diff":
                from .presets import preset_diff
                name = args.get("name", "")
                try:
                    diff = preset_diff(name)
                    return {"ok": True, "diff": diff}
                except ValueError as e:
                    return {"ok": False, "error": str(e)}
            return {"ok": False, "error": f"Unknown presets action: {subcmd}"}
        elif cmd == "filters":
            subcmd = args.get("action", "list")
            if subcmd == "list":
                from .filter_meta import PIPELINE_FILTERS
                filters_cfg = self.config.raw.get("filters", {})
                result = {}
                for pipeline_name, filter_names in PIPELINE_FILTERS.items():
                    result[pipeline_name] = []
                    for fname in filter_names:
                        fc = filters_cfg.get(fname, {})
                        result[pipeline_name].append({
                            "name": fname,
                            "enabled": fc.get("enabled", False),
                            "config": {k: v for k, v in fc.items() if k != "enabled"},
                        })
                return {"ok": True, "pipelines": result}
            elif subcmd == "update":
                name = args.get("name", "")
                if not name:
                    return {"ok": False, "error": "filter name required"}
                if name not in self.config.raw.get("filters", {}):
                    return {"ok": False, "error": f"Unknown filter: {name}"}
                if "enabled" in args:
                    self.config.raw["filters"][name]["enabled"] = bool(args["enabled"])
                if "params" in args:
                    for k, v in args["params"].items():
                        if k != "enabled":
                            self.config.raw["filters"][name][k] = v
                self._propagate_config()
                from .config import _validate
                _validate(self.config.raw)
                save_config(self.config)
                return {"ok": True}
            return {"ok": False, "error": f"Unknown filters action: {subcmd}"}
        elif cmd == "add_interface":
            host = args.get("host", "").strip()
            port = args.get("port", 0)
            if not host:
                return {"ok": False, "error": "host required"}
            try:
                port = int(port)
                if not (1 <= port <= 65535):
                    raise ValueError
            except (ValueError, TypeError):
                return {"ok": False, "error": "port must be 1-65535"}
            return self._add_tcp_client_interface(host, port)
        elif cmd == "remove_tcp_peer":
            name = args.get("name", "").strip()
            if not name:
                return {"ok": False, "error": "name required (e.g. 'TCP 1.2.3.4:4242')"}
            return self._remove_tcp_client_interface(name)
        elif cmd == "remove_tcp_server":
            name = args.get("name", "").strip()
            if not name:
                return {"ok": False, "error": "name required (e.g. 'TCP Server 0.0.0.0:4242')"}
            return self._remove_tcp_server_interface(name)
        elif cmd == "add_tcp_server":
            listen_ip = args.get("listen_ip", "0.0.0.0").strip()
            port = args.get("port", 0)
            try:
                port = int(port)
                if not (1 <= port <= 65535):
                    raise ValueError
            except (ValueError, TypeError):
                return {"ok": False, "error": "port must be 1-65535"}
            return self._add_tcp_server_interface(listen_ip, port)
        elif cmd == "add_lora_interface":
            port = args.get("port", "").strip()
            if not port:
                return {"ok": False, "error": "port required (e.g. /dev/ttyUSB0 or COM3)"}
            try:
                frequency = int(args.get("frequency", 868_000_000))
                bandwidth = int(args.get("bandwidth", 125_000))
                txpower = int(args.get("txpower", 17))
                sf = int(args.get("spreading_factor", 8))
                cr = int(args.get("coding_rate", 5))
            except (TypeError, ValueError) as e:
                return {"ok": False, "error": f"Invalid radio parameter: {e}"}
            if not (2 <= txpower <= 23):
                return {"ok": False, "error": "txpower must be 2–23 dBm"}
            mode = str(args.get("mode", "full")).strip() or "full"
            return self._add_lora_interface(port, frequency, bandwidth, txpower, sf, cr, mode=mode)
        elif cmd == "remove_lora_interface":
            name = args.get("name", "").strip()
            if not name:
                return {"ok": False, "error": "name required (e.g. 'LoRa /dev/ttyUSB0')"}
            return self._remove_lora_interface(name)
        elif cmd == "add_i2p_server":
            return self._add_i2p_server_interface()
        elif cmd == "remove_i2p_server":
            return self._remove_i2p_server_interface()
        elif cmd == "add_i2p_peer":
            b32 = args.get("b32", "").strip()
            if not b32:
                return {"ok": False, "error": "b32 address required"}
            from .i2p import validate_b32_address
            if not validate_b32_address(b32):
                return {"ok": False, "error": "Invalid B32 address (expected 52 base32 chars + .b32.i2p)"}
            return self._add_i2p_peer_interface(b32)
        elif cmd == "remove_i2p_peer":
            name = args.get("name", "").strip()
            if not name:
                return {"ok": False, "error": "name required (e.g. 'I2P Peer mrwqlsio')"}
            return self._remove_i2p_peer_interface(name)
        elif cmd == "registry":
            action = args.get("action", "status")
            if action == "status":
                return {"ok": True, "registry": self.registry.status()}
            elif action == "list":
                return {
                    "ok": True,
                    "gateways": self.registry.cached_list(),
                    "count": len(self.registry._discovered),
                }
            elif action == "discover":
                entries = self.registry.discover()
                return {
                    "ok": True,
                    "gateways": [e.__dict__ for e in entries],
                    "count": len(entries),
                }
            elif action == "register":
                # Run on a worker thread so RNS announce() can never block the
                # control socket. register() handles its own errors and logging.
                threading.Thread(
                    target=self.registry.register,
                    daemon=True,
                    name="rat-register",
                ).start()
                return {"ok": True, "queued": True}
            elif action == "deregister":
                threading.Thread(
                    target=self.registry.deregister,
                    daemon=True,
                    name="rat-deregister",
                ).start()
                return {"ok": True, "queued": True}
            elif action == "connect":
                identity_hash = args.get("identity_hash", "")
                if not identity_hash:
                    return {"ok": False, "error": "identity_hash required"}
                # Find entry in discovered list
                entry = None
                for e in self.registry._discovered:
                    if e.identity_hash == identity_hash:
                        entry = e
                        break
                if entry is None:
                    return {"ok": False, "error": f"Gateway {identity_hash[:16]} not in discovered list"}
                result = self._add_i2p_peer_interface(entry.b32)
                return result
            elif action == "set_config":
                return self._handle_registry_set_config(args)
            return {"ok": False, "error": f"Unknown registry action: {action}"}
        elif cmd == "shutdown":
            self._shutdown.set()
            return {"ok": True}
        else:
            return {"ok": False, "error": f"Unknown command: {cmd}"}

    def _add_tcp_client_interface(self, host: str, port: int) -> dict:
        """Add a TCP client interface at runtime."""
        try:
            import RNS
            from RNS.Interfaces.TCPInterface import TCPClientInterface

            name = f"TCP {host}:{port}"

            # Duplicate check — also guard against stale Down objects left after
            # a previous remove() (same pattern as I2P peer re-add logic).
            tracked_names = {p.get("name", "") for p in self._tcp_peers}
            for iface in RNS.Transport.interfaces:
                if getattr(iface, "name", "") == name:
                    if name not in tracked_names:
                        # Previously removed, stale Down object — allow re-add
                        log.info(
                            "TCP peer %s found in transport but not tracked "
                            "(previously removed, likely Down) — allowing re-add",
                            name,
                        )
                        continue
                    return {"ok": False, "error": f"Already connected to {host}:{port}"}

            config = {"name": name, "target_host": host, "target_port": str(port)}
            interface = TCPClientInterface(RNS.Transport, config)
            self._rns_instance._add_interface(interface)
            log.info("Added TCP client interface: %s:%d", host, port)

            # Track with "new" flag so TUI shows "Connecting" on first add
            self._tcp_peers.append({"name": name, "host": host, "port": port, "new": True})

            self._persist_tcp_interface(name, host, port)

            return {"ok": True, "name": name}
        except Exception as e:
            log.error("Failed to add TCP interface %s:%d: %s", host, port, e)
            return {"ok": False, "error": str(e)}

    def _remove_tcp_client_interface(self, name: str) -> dict:
        """Detach a live TCP client interface by name and remove it from the RNS config.

        Mirrors _remove_i2p_peer_interface: detaches the interface object,
        clears in-memory tracking, and removes the section from the RNS config
        so it does not reappear after restart.
        """
        try:
            import RNS

            is_shared_client = getattr(
                self._rns_instance, "is_connected_to_shared_instance", False
            )

            target = None
            for iface in list(RNS.Transport.interfaces):
                if getattr(iface, "name", "") == name:
                    target = iface
                    break

            if target is None:
                log.debug("TCP client interface %s not found in live transport", name)
            else:
                try:
                    if hasattr(target, "detach"):
                        target.detach()
                except Exception as e:
                    log.warning("Error detaching TCP client interface %s: %s", name, e)

                try:
                    RNS.Transport.interfaces.remove(target)
                except (ValueError, AttributeError):
                    pass

                try:
                    remaining = [
                        i for i in RNS.Transport.interfaces
                        if getattr(i, "name", "") != name
                    ]
                    if len(remaining) < len(RNS.Transport.interfaces):
                        RNS.Transport.interfaces[:] = remaining
                except Exception as e:
                    log.debug("Could not filter transport interfaces: %s", e)

            # Remove from in-memory tracking
            self._tcp_peers = [p for p in self._tcp_peers if p.get("name") != name]

            # Remove from RNS config file
            self._unpersist_tcp_interface(name)

            if is_shared_client:
                log.info(
                    "TCP peer %s detached (interface marked Down) and removed from config.",
                    name,
                )
            else:
                log.info("Removed TCP client interface: %s", name)

            return {"ok": True, "name": name}
        except Exception as e:
            log.error("Failed to remove TCP client interface %s: %s", name, e)
            return {"ok": False, "error": str(e)}

    def _unpersist_tcp_interface(self, name: str):
        """Remove a named TCPClientInterface section from the RNS config file."""
        try:
            from .ctl import _remove_rns_interface
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"
            if config_file.exists():
                removed = _remove_rns_interface(config_file, name)
                if removed:
                    log.info("Removed TCP interface %s from %s", name, config_file)
                else:
                    log.debug("TCP interface %s not found in %s (already removed?)", name, config_file)
        except Exception as e:
            log.warning("Failed to unpersist TCP interface %s: %s", name, e)

    def _sync_tcp_peers_from_transport(self):
        """Backfill _tcp_peers from the RNS config file at startup.

        Called once after _init_reticulum().  Reads persisted TCPClientInterface
        sections from the RNS config file and populates _tcp_peers so the TUI
        shows them immediately on a fresh start without requiring a manual add.

        The status (Connecting/Connected) is determined at runtime by the
        status command scanning RNS.Transport.interfaces every 5 seconds.
        """
        try:
            from .ctl import _list_rns_interfaces
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"

            if not config_file.exists():
                return

            # Read raw config to find TCPClientInterface sections
            try:
                from configobj import ConfigObj
                cfg = ConfigObj(str(config_file))
                ifaces = cfg.get("interfaces", {})
            except ImportError:
                ifaces = {}

            existing_names = {p.get("name", "") for p in self._tcp_peers}
            count = 0
            for iface_name, iface_cfg in ifaces.items():
                if not isinstance(iface_cfg, dict):
                    continue
                if iface_cfg.get("type", "").strip() != "TCPClientInterface":
                    continue
                host = iface_cfg.get("target_host", "").strip()
                port_str = iface_cfg.get("target_port", "").strip()
                if not host or not port_str:
                    continue
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                name = iface_name.strip()
                if name in existing_names:
                    continue
                self._tcp_peers.append({"name": name, "host": host, "port": port})
                existing_names.add(name)
                count += 1
                log.info("Loaded TCP peer from config at startup: %s (%s:%d)", name, host, port)
            if count:
                log.info("Backfilled %d TCP peer(s) from RNS config", count)
        except Exception as e:
            log.warning("Could not load TCP peers from config at startup: %s", e)

    def _add_tcp_server_interface(self, listen_ip: str, port: int) -> dict:
        """Add a TCP server (listener) interface at runtime."""
        try:
            import RNS
            from RNS.Interfaces.TCPInterface import TCPServerInterface

            name = f"TCP Server {listen_ip}:{port}"

            # Duplicate check — skip stale Down objects not in tracking (re-add after remove)
            tracked_names = {s.get("name", "") for s in self._tcp_servers}
            for iface in RNS.Transport.interfaces:
                if getattr(iface, "name", "") == name:
                    if name not in tracked_names:
                        log.info(
                            "TCP server %s found in transport but not tracked "
                            "(previously removed, likely Down) — allowing re-add",
                            name,
                        )
                        continue
                    return {"ok": False, "error": f"Already listening on {listen_ip}:{port}"}

            config = {"name": name, "listen_ip": listen_ip, "listen_port": str(port)}
            interface = TCPServerInterface(RNS.Transport, config)
            self._rns_instance._add_interface(interface)
            log.info("Added TCP server interface: %s:%d", listen_ip, port)

            # Track with "new" flag so TUI shows "Activating" on first add
            self._tcp_servers.append({"name": name, "listen_ip": listen_ip, "port": port, "new": True})

            self._persist_tcp_server_interface(name, listen_ip, port)

            return {"ok": True, "name": name}
        except Exception as e:
            log.error("Failed to add TCP server %s:%d: %s", listen_ip, port, e)
            return {"ok": False, "error": str(e)}

    def _remove_tcp_server_interface(self, name: str) -> dict:
        """Detach a live TCP server interface by name and remove it from the RNS config."""
        try:
            import RNS

            is_shared_client = getattr(
                self._rns_instance, "is_connected_to_shared_instance", False
            )

            target = None
            for iface in list(RNS.Transport.interfaces):
                if getattr(iface, "name", "") == name:
                    target = iface
                    break

            if target is None:
                log.debug("TCP server interface %s not found in live transport", name)
            else:
                try:
                    if hasattr(target, "detach"):
                        target.detach()
                except Exception as e:
                    log.warning("Error detaching TCP server interface %s: %s", name, e)

                try:
                    RNS.Transport.interfaces.remove(target)
                except (ValueError, AttributeError):
                    pass

                try:
                    remaining = [
                        i for i in RNS.Transport.interfaces
                        if getattr(i, "name", "") != name
                    ]
                    if len(remaining) < len(RNS.Transport.interfaces):
                        RNS.Transport.interfaces[:] = remaining
                except Exception as e:
                    log.debug("Could not filter transport interfaces: %s", e)

            # Remove from in-memory tracking
            self._tcp_servers = [s for s in self._tcp_servers if s.get("name") != name]

            # Remove from RNS config file
            self._unpersist_tcp_server_interface(name)

            if is_shared_client:
                log.info(
                    "TCP server %s detached (interface marked Down) and removed from config.",
                    name,
                )
            else:
                log.info("Removed TCP server interface: %s", name)

            return {"ok": True, "name": name}
        except Exception as e:
            log.error("Failed to remove TCP server interface %s: %s", name, e)
            return {"ok": False, "error": str(e)}

    def _unpersist_tcp_server_interface(self, name: str):
        """Remove a named TCPServerInterface section from the RNS config file."""
        try:
            from .ctl import _remove_rns_interface
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"
            if config_file.exists():
                removed = _remove_rns_interface(config_file, name)
                if removed:
                    log.info("Removed TCP server %s from %s", name, config_file)
                else:
                    log.debug("TCP server %s not found in %s (already removed?)", name, config_file)
        except Exception as e:
            log.warning("Failed to unpersist TCP server %s: %s", name, e)

    def _sync_tcp_servers_from_transport(self):
        """Backfill _tcp_servers from the RNS config file at startup.

        Called once after _init_reticulum().  Reads persisted TCPServerInterface
        sections from the RNS config file and populates _tcp_servers so the TUI
        shows them immediately on a fresh start without requiring a manual add.
        """
        try:
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"

            if not config_file.exists():
                return

            try:
                from configobj import ConfigObj
                cfg = ConfigObj(str(config_file))
                ifaces = cfg.get("interfaces", {})
            except ImportError:
                ifaces = {}

            existing_names = {s.get("name", "") for s in self._tcp_servers}
            count = 0
            for iface_name, iface_cfg in ifaces.items():
                if not isinstance(iface_cfg, dict):
                    continue
                if iface_cfg.get("type", "").strip() != "TCPServerInterface":
                    continue
                listen_ip = iface_cfg.get("listen_ip", "0.0.0.0").strip()
                port_str = iface_cfg.get("listen_port", "").strip()
                if not port_str:
                    continue
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                name = iface_name.strip()
                if name in existing_names:
                    continue
                self._tcp_servers.append({"name": name, "listen_ip": listen_ip, "port": port})
                existing_names.add(name)
                count += 1
                log.info("Loaded TCP server from config at startup: %s (%s:%d)", name, listen_ip, port)
            if count:
                log.info("Backfilled %d TCP server(s) from RNS config", count)
        except Exception as e:
            log.warning("Could not load TCP servers from config at startup: %s", e)

    def _persist_tcp_server_interface(self, name: str, listen_ip: str, port: int):
        """Write the TCP server interface to RNS config for persistence."""
        try:
            from .ctl import _add_rns_tcp_interface
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"
            if config_file.exists():
                _add_rns_tcp_interface(config_file, "server", name, listen_ip, port)
                log.info("Persisted TCP server %s to %s", name, config_file)
        except Exception as e:
            log.warning("TCP server active but failed to persist: %s", e)

    def _add_i2p_server_interface(self) -> dict:
        """Add a connectable I2P server interface at runtime."""
        try:
            import RNS
            from RNS.Interfaces.I2PInterface import I2PInterface as RNS_I2PInterface

            # Check if already have a connectable I2P interface.
            # In shared-instance mode the interface name in RNS may differ from
            # what we assigned, so check by type + connectable flag only.
            for iface in RNS.Transport.interfaces:
                if "I2P" in type(iface).__name__ and getattr(iface, "connectable", False):
                    b32 = getattr(iface, "b32", None)
                    return {
                        "ok": False,
                        "error": "I2P server already running"
                        + (f" ({b32[:16]}...)" if b32 else ""),
                    }

            from .i2p import probe_sam_api
            if not probe_sam_api():
                return {"ok": False, "error": "i2pd SAM API not reachable — is i2pd running?"}

            name = "I2P Gateway"
            config = {
                "name": name,
                "storagepath": RNS.Reticulum.storagepath,
                "connectable": True,
            }
            interface = RNS_I2PInterface(RNS.Transport, config)
            self._rns_instance._add_interface(interface)
            self._i2p_interfaces.append(interface)
            log.info("Added I2P server interface: %s", name)

            self._persist_i2p_server_interface(name)

            # B32 may not be available immediately (tunnel establishment)
            b32 = getattr(interface, "b32", None)
            result = {"ok": True, "name": name}
            if b32:
                result["b32"] = str(b32)
            return result
        except Exception as e:
            log.error("Failed to add I2P server: %s", e)
            return {"ok": False, "error": str(e)}

    def _remove_i2p_server_interface(self) -> dict:
        """Detach and remove the connectable I2P server interface (I2P Gateway).

        Mirrors _remove_i2p_peer_interface() but targets the connectable
        interface added by _add_i2p_server_interface().  The interface name
        is always "I2P Gateway" (set in _add_i2p_server_interface).
        """
        name = "I2P Gateway"
        try:
            import RNS

            is_shared_client = getattr(
                self._rns_instance, "is_connected_to_shared_instance", False
            )

            target = None
            for iface in list(RNS.Transport.interfaces):
                if "I2P" in type(iface).__name__ and getattr(iface, "connectable", False):
                    target = iface
                    name = getattr(iface, "name", name)
                    break

            if target is None:
                log.debug("I2P server interface not found in live transport")
            else:
                try:
                    if hasattr(target, "detach"):
                        target.detach()
                except Exception as e:
                    log.warning("Error detaching I2P server interface: %s", e)

                try:
                    RNS.Transport.interfaces.remove(target)
                except (ValueError, AttributeError):
                    pass

                try:
                    remaining = [
                        i for i in RNS.Transport.interfaces
                        if i is not target
                    ]
                    if len(remaining) < len(RNS.Transport.interfaces):
                        RNS.Transport.interfaces[:] = remaining
                except Exception as e:
                    log.debug("Could not filter transport interfaces: %s", e)

                self._i2p_interfaces = [
                    i for i in self._i2p_interfaces if i is not target
                ]

            # Remove from RNS config file
            self._unpersist_i2p_interface(name)

            if is_shared_client:
                log.info(
                    "I2P server %s detached and removed from config. "
                    "SAM session may linger in i2pd until rnsd restarts.",
                    name,
                )
            else:
                log.info("Removed I2P server interface: %s", name)

            return {"ok": True, "name": name}
        except Exception as e:
            log.error("Failed to remove I2P server interface: %s", e)
            return {"ok": False, "error": str(e)}

    def _persist_i2p_server_interface(self, name: str):
        """Write the I2P server interface to RNS config for persistence."""
        try:
            from .i2p import add_rns_i2p_interface
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"
            if config_file.exists():
                add_rns_i2p_interface(config_file, name, connectable=True)
                log.info("Persisted I2P server %s to %s", name, config_file)
        except Exception as e:
            log.warning("I2P server active but failed to persist: %s", e)

    def _sync_i2p_peers_from_transport(self):
        """Backfill _i2p_peers from the RNS config file at startup.

        Called once after _init_reticulum().  Reads the persisted
        [[I2PInterface]] sections (connectable=no) from the RNS config file
        and populates _i2p_peers so the TUI shows them immediately on a
        fresh start without requiring a manual add via the TUI.

        The status (Checking/Connected) is determined at runtime by the
        status command scanning RNS.Transport.interfaces every 5 seconds.
        """
        try:
            from .i2p import list_rns_i2p_peers
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"

            existing_names = {p.get("name", "") for p in self._i2p_peers}
            count = 0
            for entry in list_rns_i2p_peers(config_file):
                b32 = entry.get("b32", "").strip()
                if not b32:
                    continue
                short_name = f"I2P Peer {b32[:8]}"
                if short_name in existing_names:
                    continue
                self._i2p_peers.append({"name": short_name, "b32": b32})
                existing_names.add(short_name)
                count += 1
                log.info("Loaded I2P peer from config at startup: %s (%s)", short_name, b32[:16])
            if count:
                log.info("Backfilled %d I2P peer(s) from RNS config", count)
        except Exception as e:
            log.warning("Could not load I2P peers from config at startup: %s", e)

    def _persist_tcp_interface(self, name: str, host: str, port: int):
        """Write the interface to the RNS config file for persistence across restarts."""
        try:
            from .ctl import _add_rns_tcp_interface
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"
            if config_file.exists():
                _add_rns_tcp_interface(config_file, "client", name, host, port)
                log.info("Persisted TCP interface %s to %s", name, config_file)
        except Exception as e:
            log.warning("Interface active but failed to persist to config: %s", e)

    def _add_i2p_peer_interface(self, b32_address: str) -> dict:
        """Add an I2P peer interface at runtime."""
        try:
            import RNS
            from RNS.Interfaces.I2PInterface import I2PInterface as RNS_I2PInterface

            name = f"I2P Peer {b32_address[:8]}"

            # Duplicate check — must handle both the short name we assign
            # ("I2P Peer mrwqlsio") and the long name RNS uses internally
            # ("I2P Peer mrwqlsio to mrwqlsio….b32.i2p") when running as a
            # shared-instance client where rnsd owns the interface.
            # Also check by B32 address to catch any naming variation.
            #
            # After a remove(), the interface may still linger in
            # RNS.Transport.interfaces with Status: Down (detach() marks it
            # down but rnsd keeps the object).  We allow re-add in that case
            # by checking our own _i2p_peers tracking list: if the name is
            # NOT in our tracking, the interface was already removed by us
            # and is just a stale Down object — skip it.
            tracked_names = {p.get("name", "") for p in self._i2p_peers}
            for iface in RNS.Transport.interfaces:
                iface_name = getattr(iface, "name", "") or ""
                iface_peers = getattr(iface, "peers", None) or ""
                # Match short name, long name (prefix), or B32 address
                name_match = (
                    iface_name == name
                    or iface_name.startswith(name + " ")
                    or b32_address in str(iface_peers)
                )
                if name_match:
                    # If this interface is not in our tracking list, it was
                    # previously removed (detached/Down) — allow re-add.
                    if name not in tracked_names:
                        log.info(
                            "I2P peer %s found in transport but not in tracking "
                            "(previously removed, likely Down) — allowing re-add",
                            b32_address[:16],
                        )
                        continue
                    return {"ok": False, "error": f"Already connected to {b32_address[:16]}..."}

            config = {
                "name": name,
                "storagepath": RNS.Reticulum.storagepath,
                "peers": b32_address,
                "connectable": False,
            }
            interface = RNS_I2PInterface(RNS.Transport, config)
            self._rns_instance._add_interface(interface)
            self._i2p_interfaces.append(interface)
            # Mark as "new" so the TUI shows "Connecting" (first-time tunnel
            # establishment) rather than "Checking…" (status poll after reconnect).
            # The flag is cleared once the peer becomes connected for the first time.
            self._i2p_peers.append({"name": name, "b32": b32_address, "new": True})
            log.info("Added I2P peer: %s", b32_address[:16])

            self._persist_i2p_interface(name, b32_address)
            return {"ok": True, "name": name}
        except Exception as e:
            log.error("Failed to add I2P peer %s: %s", b32_address[:16], e)
            return {"ok": False, "error": str(e)}

    def _remove_i2p_peer_interface(self, name: str) -> dict:
        """Detach a live I2P peer interface by name and remove it from the RNS config.

        Calls detach() on the interface object, which causes rnsd to mark it
        Down immediately — no traffic will flow after this point.  The underlying
        SAM session in i2pd may linger until rnsd restarts, but rnsd will not
        route packets through a Down interface.

        Also clears in-memory tracking (_i2p_peers, _i2p_interfaces) and removes
        the section from the RNS config file so the interface does not reappear
        after rnsd restarts.
        """
        try:
            import RNS

            # Detect shared-instance mode — if so, the local Transport.interfaces
            # list is a client-side proxy; removing from it does not affect rnsd.
            is_shared_client = getattr(
                self._rns_instance, "is_connected_to_shared_instance", False
            )

            target = None
            for iface in list(RNS.Transport.interfaces):
                if getattr(iface, "name", "") == name:
                    target = iface
                    break

            if target is None:
                # Not live — may still be in config; try to remove from config anyway
                log.debug("I2P peer interface %s not found in live transport", name)
            else:
                try:
                    if hasattr(target, "detach"):
                        target.detach()
                except Exception as e:
                    log.warning("Error detaching I2P peer interface %s: %s", name, e)

                try:
                    RNS.Transport.interfaces.remove(target)
                except (ValueError, AttributeError):
                    pass

                try:
                    remaining = [
                        i for i in RNS.Transport.interfaces
                        if getattr(i, "name", "") != name
                    ]
                    if len(remaining) < len(RNS.Transport.interfaces):
                        RNS.Transport.interfaces[:] = remaining
                except Exception as e:
                    log.debug("Could not filter transport interfaces: %s", e)

                # Remove from our tracking list
                self._i2p_interfaces = [
                    i for i in self._i2p_interfaces
                    if getattr(i, "name", "") != name
                ]

            # Remove from in-memory peers list
            self._i2p_peers = [p for p in self._i2p_peers if p.get("name") != name]

            # Remove from RNS config file
            self._unpersist_i2p_interface(name)

            if is_shared_client:
                log.info(
                    "I2P peer %s detached (interface marked Down by rnsd) and removed from config. "
                    "SAM session may linger in i2pd until rnsd restarts, but no traffic will flow.",
                    name,
                )
            else:
                log.info("Removed I2P peer interface: %s", name)

            return {"ok": True, "name": name}
        except Exception as e:
            log.error("Failed to remove I2P peer interface %s: %s", name, e)
            return {"ok": False, "error": str(e)}

    def _unpersist_i2p_interface(self, name: str):
        """Remove a named I2PInterface section from the RNS config file."""
        try:
            from .i2p import remove_rns_i2p_interface
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"
            if config_file.exists():
                removed = remove_rns_i2p_interface(config_file, name)
                if removed:
                    log.info("Removed I2P interface %s from %s", name, config_file)
                else:
                    log.debug("I2P interface %s not found in %s (already removed?)", name, config_file)
        except Exception as e:
            log.warning("Failed to unpersist I2P interface %s: %s", name, e)

    def _persist_i2p_interface(self, name: str, b32_address: str):
        """Write the I2P peer to the RNS config file for persistence across restarts."""
        try:
            from .i2p import add_rns_i2p_interface
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"
            if config_file.exists():
                add_rns_i2p_interface(config_file, name, peers=[b32_address])
                log.info("Persisted I2P peer %s to %s", name, config_file)
        except Exception as e:
            log.warning("I2P peer active but failed to persist: %s", e)

    def _add_lora_interface(
        self,
        port: str,
        frequency: int = 868_000_000,
        bandwidth: int = 125_000,
        txpower: int = 17,
        spreading_factor: int = 8,
        coding_rate: int = 5,
        mode: str = "full",
    ) -> dict:
        """Add an RNodeInterface (LoRa) at runtime.

        Args:
            mode: RNS interface mode written to the config — ``"full"``
                  (default, peer transport node) or ``"access_point"``.
        """
        try:
            import RNS
            from RNS.Interfaces.RNodeInterface import RNodeInterface
            from RNS.Interfaces.Interface import Interface as _RNSIface

            name = f"LoRa {port}"
            # Duplicate check
            for iface in RNS.Transport.interfaces:
                if getattr(iface, "name", "") == name:
                    return {"ok": False, "error": f"LoRa interface on {port} already active"}

            # Serial port availability check — fail fast with a clear message
            # before handing the port to RNS (which gives cryptic errors on failure)
            from .lora import check_serial_port_available
            port_ok, port_err = check_serial_port_available(port)
            if not port_ok:
                log.error("LoRa serial port check failed: %s", port_err)
                return {"ok": False, "error": port_err}

            # Translate the human-readable mode string to the RNS integer constant.
            #
            # BUG FIX: _add_interface(interface) with no mode= argument defaults to
            # MODE_FULL (= 1), which is why `rnstatus` showed "Mode: Full" even though
            # the persisted config file correctly contained `mode = access_point`.
            # The "mode" key in the config dict passed to RNodeInterface() is ignored
            # by the constructor — mode is set exclusively by _add_interface(mode=).
            _mode_map = {
                "access_point":   _RNSIface.MODE_ACCESS_POINT,    # 3
                "full":           _RNSIface.MODE_FULL,             # 1
                "gateway":        _RNSIface.MODE_GATEWAY,          # 6
                "roaming":        _RNSIface.MODE_ROAMING,          # 4
                "boundary":       _RNSIface.MODE_BOUNDARY,         # 5
                "point_to_point": _RNSIface.MODE_POINT_TO_POINT,   # 2
            }
            # Default to MODE_FULL so I2P→LoRa re-propagation works.
            # MODE_ACCESS_POINT only re-propagates FROM LoRa clients TO other
            # interfaces — it does NOT forward packets arriving from I2P/TCP
            # back to LoRa.  MODE_FULL is the correct mode for a bridging
            # transport node that needs bidirectional I2P↔LoRa forwarding.
            interface_mode = _mode_map.get(mode.lower(), _RNSIface.MODE_FULL)

            config = {
                "name": name,
                "mode": mode,
                "port": port,
                "frequency": str(frequency),
                "bandwidth": str(bandwidth),
                "txpower": str(txpower),
                "spreadingfactor": str(spreading_factor),
                "codingrate": str(coding_rate),
                "enabled": "yes",
            }
            interface = RNodeInterface(RNS.Transport, config)
            self._rns_instance._add_interface(interface, mode=interface_mode)
            log.info(
                "Added LoRa interface: %s (mode=%s, freq=%d Hz, SF%d, BW=%d Hz, %d dBm)",
                name, mode, frequency, spreading_factor, bandwidth, txpower,
            )

            self._persist_lora_interface(name, port, frequency, bandwidth, txpower, spreading_factor, coding_rate, mode=mode)

            # Auto-sync radio parameters into the airtime filter so the
            # duty-cycle estimator always uses the actual hardware settings.
            # This prevents the filter from over- or under-counting airtime
            # when the radio is configured with non-default SF or BW.
            try:
                lora_airtime_cfg = self.config.raw.setdefault("filters", {}).setdefault("lora_airtime", {})
                lora_airtime_cfg["spreading_factor"] = spreading_factor
                lora_airtime_cfg["bandwidth_hz"] = bandwidth
                self._propagate_config()
                log.info(
                    "Auto-synced lora_airtime filter: SF%d, BW=%d Hz (from LoRa interface %s)",
                    spreading_factor, bandwidth, name,
                )
            except Exception as _sync_err:
                log.warning("Failed to auto-sync lora_airtime filter params: %s", _sync_err)

            return {
                "ok": True,
                "name": name,
                "port": port,
                "frequency": frequency,
                "bandwidth": bandwidth,
                "txpower": txpower,
                "spreading_factor": spreading_factor,
                "coding_rate": coding_rate,
                "mode": mode,
            }
        except ImportError:
            return {"ok": False, "error": "RNodeInterface not available in this RNS version"}
        except Exception as e:
            log.error("Failed to add LoRa interface on %s: %s", port, e)
            return {"ok": False, "error": str(e)}

    def _remove_lora_interface(self, name: str) -> dict:
        """Detach a live LoRa interface by name and remove it from the RNS config."""
        try:
            import RNS
            from .lora import is_lora_interface

            # Find the interface object in the live transport list
            target = None
            for iface in list(RNS.Transport.interfaces):
                if getattr(iface, "name", "") == name and is_lora_interface(iface):
                    target = iface
                    break

            if target is None:
                return {"ok": False, "error": f"LoRa interface '{name}' not found"}

            # Detach from RNS transport
            try:
                if hasattr(target, "detach"):
                    target.detach()
            except Exception as e:
                log.warning("Error detaching LoRa interface %s: %s", name, e)

            # Remove from transport list — use name-based filter as fallback
            # because RNS.Transport.interfaces may not support .remove() by identity
            try:
                RNS.Transport.interfaces.remove(target)
            except (ValueError, AttributeError):
                pass
            # Belt-and-suspenders: also filter by name in case .remove() silently failed
            try:
                remaining = [
                    i for i in RNS.Transport.interfaces
                    if getattr(i, "name", "") != name
                ]
                if len(remaining) < len(RNS.Transport.interfaces):
                    RNS.Transport.interfaces[:] = remaining
            except Exception as e:
                log.debug("Could not filter transport interfaces: %s", e)

            log.info("Removed LoRa interface: %s", name)

            # Remove from persisted RNS config
            self._unpersist_lora_interface(name)

            return {"ok": True, "name": name}
        except Exception as e:
            log.error("Failed to remove LoRa interface %s: %s", name, e)
            return {"ok": False, "error": str(e)}

    def _unpersist_lora_interface(self, name: str):
        """Remove a named RNodeInterface section from the RNS config file."""
        try:
            from .lora import remove_rns_lora_interface
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"
            if config_file.exists():
                removed = remove_rns_lora_interface(config_file, name)
                if removed:
                    log.info("Removed LoRa interface %s from %s", name, config_file)
                else:
                    log.debug("LoRa interface %s not found in %s (already removed?)", name, config_file)
        except Exception as e:
            log.warning("Failed to unpersist LoRa interface %s: %s", name, e)

    def _persist_lora_interface(
        self,
        name: str,
        port: str,
        frequency: int,
        bandwidth: int,
        txpower: int,
        spreading_factor: int,
        coding_rate: int,
        mode: str = "full",
    ):
        """Write the RNodeInterface to the RNS config file for persistence."""
        try:
            from .lora import add_rns_rnode_interface
            from .ctl import _ensure_rns_config
            rns_config_path = self.config.general.get("reticulum_config_path", "") or None
            if rns_config_path:
                config_file = Path(rns_config_path) / "config"
            else:
                config_file = _default_rns_dir() / "config"
            # Create the config file if it doesn't exist yet so the interface
            # is persisted even on a first-run or non-default-path setup.
            _ensure_rns_config(config_file)
            add_rns_rnode_interface(
                config_file, name, port,
                frequency=frequency,
                bandwidth=bandwidth,
                txpower=txpower,
                spreadingfactor=spreading_factor,
                codingrate=coding_rate,
                mode=mode,
            )
            log.info("Persisted LoRa interface %s (mode=%s) to %s", name, mode, config_file)
        except Exception as e:
            log.warning("LoRa interface active but failed to persist: %s", e)

    def _propagate_config(self):
        """Push current config to all subsystems that cache config values."""
        self.router.rebuild(self.config)
        for name, subsystem, section in [
            ("reputation", self.reputation, self.config.reputation),
            ("blackhole", self.blackhole, self.config.blackhole),
            ("adaptive", self.adaptive, self.config.adaptive),
            ("correlator", self.correlator, self.config.correlator),
        ]:
            try:
                subsystem.refresh_config(section)
            except Exception as e:
                log.error("Failed to propagate config to %s: %s", name, e)
        self.correlator._dry_run = self.config.dry_run
        try:
            self.registry.refresh_config(self.config.raw.get("registry", {}))
        except Exception as e:
            log.error("Failed to propagate config to registry: %s", e)
        self.event_bus.emit(SecurityEvent(
            event_type=EventType.CONFIG_CHANGED,
            severity=EventSeverity.NOTICE,
            source="daemon",
            description="Configuration propagated to all subsystems",
        ))
        log.info("Config propagated to all subsystems")

    def _check_auto_blackhole(self):
        """Check all reputation scores and auto-blackhole identities below threshold."""
        for identity_hash, rep in self.reputation.identities_snapshot():
            if rep.pinned:
                continue
            if self.reputation.should_auto_blackhole(identity_hash):
                added = self.blackhole.add(
                    identity_hash,
                    reason=f"auto-blackhole: reputation {rep.effective_score:.3f}",
                    auto=True,
                )
                if added:
                    self.reputation.record_auto_blackhole()
                    log.warning(
                        "Auto-blackholed %s (score %.3f)",
                        identity_hash[:16], rep.effective_score,
                    )
                    self.event_bus.emit(SecurityEvent(
                        event_type=EventType.IDENTITY_BLACKHOLED,
                        severity=EventSeverity.ALERT,
                        source="auto_blackhole",
                        identity_hash=identity_hash,
                        description=f"Auto-blackholed {identity_hash[:16]} (score {rep.effective_score:.3f})",
                    ))

    def _handle_signal(self, signum, frame):
        log.info("Received signal %d", signum)
        self.stop()

    def _handle_sighup(self, signum, frame):
        """SIGHUP triggers config hot-reload."""
        log.info("SIGHUP received — reloading config")
        self.config = reload_config(self.config)
        self._propagate_config()
        # No save_config here — SIGHUP reloads FROM disk, not TO disk

    def _handle_registry_set_config(self, args: dict) -> dict:
        """Handle registry set_config RPC — toggle registry options at runtime."""
        reg_cfg = self.config.raw.setdefault("registry", {})

        was_publish = reg_cfg.get("publish", False)

        for key in ("enabled", "publish", "discover", "auto_connect"):
            if key in args:
                reg_cfg[key] = bool(args[key])

        for key in ("announce_interval", "discover_interval"):
            if key in args:
                try:
                    reg_cfg[key] = max(10, int(args[key]))
                except (TypeError, ValueError):
                    pass

        self.registry.refresh_config(reg_cfg)

        # Handle publish toggle
        now_publish = reg_cfg.get("publish", False)
        if now_publish and not was_publish:
            try:
                self.registry.init_gateway_destination()
                self.registry.register()
            except Exception as e:
                log.warning("Registry publish activation failed: %s", e)
        elif was_publish and not now_publish:
            try:
                self.registry.deregister()
            except Exception as e:
                log.debug("Registry deregister on unpublish: %s", e)

        log.info("Registry config updated: enabled=%s publish=%s discover=%s auto_connect=%s",
                 reg_cfg.get("enabled"), reg_cfg.get("publish"),
                 reg_cfg.get("discover"), reg_cfg.get("auto_connect"))

        save_config(self.config)
        return {"ok": True, "registry": self.registry.status()}
