"""High-level wrappers around the aircrack-ng suite."""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.core import parsers
from app.core.process_runner import ProcessRunner
from app.core.state import SessionState, Station

REQUIRED_BINARIES = [
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "aircrack-ng",
]

OnLine = Callable[[str], None]
OnDone = Callable[[int], None]


class AircrackService:
    def __init__(
        self,
        state: SessionState,
        *,
        captures_dir: Optional[Path] = None,
        log: Optional[OnLine] = None,
    ) -> None:
        self.session = state
        self.log = log or (lambda _msg: None)
        root = Path(__file__).resolve().parents[2]
        self.captures_dir = captures_dir or (root / "captures")
        self.captures_dir.mkdir(parents=True, exist_ok=True)

        self._scan_runner = ProcessRunner()
        self._capture_runner = ProcessRunner()
        self._deauth_runner = ProcessRunner()
        self._crack_runner = ProcessRunner()
        self._helper = ProcessRunner()

        self._scan_prefix: Optional[Path] = None
        self._capture_prefix: Optional[Path] = None
        self._handshake_stop_scheduled = False
        self._installing_tools = False

    # ------------------------------------------------------------------ utils
    def missing_binaries(self) -> list[str]:
        return parsers.which_missing(REQUIRED_BINARIES)

    def is_root(self) -> bool:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        return False

    def _emit(self, msg: str) -> None:
        self.log(msg)

    def stop_all(self) -> None:
        for runner in (
            self._scan_runner,
            self._capture_runner,
            self._deauth_runner,
            self._crack_runner,
        ):
            runner.stop(force=True)

    # ------------------------------------------------------------- interfaces
    def list_interfaces(self) -> list[str]:
        """Discover wireless ifaces via iwconfig, iw, airmon-ng, ip, and sysfs."""
        found: set[str] = set()

        _c, iwc = self._helper.run_capture(["iwconfig"])
        found.update(parsers.parse_wireless_interfaces(iwc or ""))

        _c, iw_out = self._helper.run_capture(["iw", "dev"])
        found.update(parsers.parse_iw_interfaces(iw_out or ""))

        _c, airmon = self._helper.run_capture(["airmon-ng"])
        for line in (airmon or "").splitlines():
            parts = re.split(r"\t+|\s{2,}", line.strip())
            if len(parts) < 2:
                continue
            if not parts[0].lower().startswith("phy"):
                continue
            if parts[0].strip().upper() == "PHY":
                continue
            iface = parts[1].strip()
            if iface and iface.lower() not in ("interface", "driver", "chipset"):
                found.add(iface)

        _c, ip_out = self._helper.run_capture(["ip", "link", "show"])
        found.update(parsers.parse_ip_link_wireless_hint(ip_out or ""))

        # sysfs: any netdev with a wireless/phy80211 node
        try:
            net = Path("/sys/class/net")
            if net.is_dir():
                for entry in net.iterdir():
                    name = entry.name
                    if (entry / "wireless").exists() or (entry / "phy80211").exists():
                        found.add(name)
        except OSError:
            pass

        mon = self.session.monitor_interface
        if mon:
            found.add(mon)

        # Drop obvious non-ifaces
        return sorted(
            n
            for n in found
            if n
            and not n.startswith("(")
            and n.lower() not in ("interface", "driver", "chipset")
        )

    def probe_adapter_status(self) -> dict:
        """Explain why Interface may be empty even when USB Wi-Fi is plugged in."""
        ifaces = self.list_interfaces()
        _c, lsusb = self._helper.run_capture(["lsusb"], timeout=10)
        usb_lines = []
        for line in (lsusb or "").splitlines():
            low = line.lower()
            if any(
                k in low
                for k in (
                    "wireless",
                    "802.11",
                    "realtek",
                    "ralink",
                    "atheros",
                    "0bda:",
                    "2357:",
                    "148f:",
                    "0cf3:",
                )
            ):
                if "root hub" in low or "virtualbox" in low:
                    continue
                usb_lines.append(line.strip())

        loaded: list[str] = []
        _c, lsmod = self._helper.run_capture(["lsmod"], timeout=8)
        for mod in (
            "8188eu",
            "8192eu",
            "rtl8xxxu",
            "r8188eu",
            "88XXau",
            "8812au",
            "mac80211",
        ):
            if re.search(rf"^{re.escape(mod)}\b", lsmod or "", re.M):
                loaded.append(mod)

        return {
            "ifaces": ifaces,
            "usb": usb_lines,
            "modules": loaded,
            "has_usb": bool(usb_lines),
            "has_iface": bool(ifaces),
        }

    def try_bring_up_wifi(self) -> list[str]:
        """Best-effort: unblock rfkill, modprobe common Realtek modules, return ifaces."""
        notes: list[str] = []
        self._helper.run_capture(["rfkill", "unblock", "all"], timeout=10)
        notes.append("rfkill unblock all")

        # Prefer good DKMS modules; unload known-bad stock first when present
        for bad in ("rtl8xxxu", "r8188eu"):
            code, _ = self._helper.run_capture(["rmmod", bad], timeout=15)
            if code == 0:
                notes.append(f"rmmod {bad}")

        for mod in ("8188eu", "8192eu", "88XXau", "8812au"):
            code, out = self._helper.run_capture(["modprobe", mod], timeout=20)
            if code == 0:
                notes.append(f"modprobe {mod} ok")
            elif out and "not found" not in (out or "").lower():
                notes.append(f"modprobe {mod}: {(out or '').strip()[:120]}")

        time.sleep(1.5)
        ifaces = self.list_interfaces()
        for iface in ifaces:
            self._helper.run_capture(["ip", "link", "set", iface, "up"], timeout=8)
            notes.append(f"ip link set {iface} up")
        return notes

    # ----------------------------------------------------------- monitor mode
    # ----------------------------------------------------------- monitor mode
    # These Realtek out-of-tree drivers are NOT mac80211 — `iw set type monitor`
    # fails with -95 / Operation not supported. Use iwconfig instead.
    IOCTL_MONITOR_DRIVERS = frozenset(
        {
            "8192eu",
            "rtl8192eu",
            "8188eu",
            "r8188eu",
            "8812au",
            "8814au",
            "8821au",
            "88XXau",
            "rtl88xxau",
        }
    )

    def check_kill(self) -> tuple[bool, str]:
        self._emit("Running: airmon-ng check kill")
        code, out = self._helper.run_capture(["airmon-ng", "check", "kill"])
        self._emit(out.strip() or "(no output)")
        return code == 0, out

    def _iface_driver(self, interface: str) -> str:
        link = Path(f"/sys/class/net/{interface}/device/driver")
        try:
            if link.exists() or link.is_symlink():
                return link.resolve().name
        except OSError:
            pass
        return ""

    def _uses_ioctl_monitor(self, interface: str) -> bool:
        driver = self._iface_driver(interface).lower()
        if not driver:
            return False
        if driver in {d.lower() for d in self.IOCTL_MONITOR_DRIVERS}:
            return True
        # Heuristic: many Realtek dkms modules
        return any(x in driver for x in ("8192eu", "8188eu", "88xxau", "8812au", "8814au"))

    def start_monitor(
        self,
        interface: str,
        *,
        auto_check_kill: bool = True,
        force_reset: bool = False,
    ) -> tuple[bool, str, Optional[str]]:
        if auto_check_kill:
            self._emit(
                "Auto check kill: stopping NetworkManager / wpa_supplicant "
                "(required for reliable scanning on Realtek)"
            )
            self.check_kill()
            self._helper.run_capture(["rfkill", "unblock", "all"])

        existing = self._discover_monitor_iface(preferred=interface)
        if existing and not force_reset:
            self._helper.run_capture(["ip", "link", "set", existing, "up"])
            self.session.interface = interface
            self.session.monitor_interface = existing
            self._emit(f"Monitor already active on {existing}")
            self._log_iface_diag(existing)
            return True, f"Monitor already active on {existing}", existing

        self._emit(f"Running: airmon-ng start {interface}")
        code, out = self._helper.run_capture(["airmon-ng", "start", interface])
        self._emit(out.strip() or "(no output)")
        mon = parsers.parse_airmon_monitor_iface(out)

        if not mon and parsers.AIRMON_ENABLED_BARE_RE.search(out or ""):
            mon = interface

        # airmon often prints "monitor mode enabled" for Realtek even when the
        # iface is still Managed — only trust real Mode:Monitor / type monitor.
        if mon and not self._discover_monitor_iface(preferred=mon):
            self._emit(
                "airmon-ng claimed monitor, but iwconfig still shows Managed — "
                "trying driver-specific enable…"
            )
            ok_set, set_out = self._enable_monitor(mon)
            out = (out or "") + "\n" + set_out
            if not ok_set:
                mon = None

        if not mon:
            mon = self._discover_monitor_iface(preferred=interface)

        if not mon:
            self._emit(
                f"Trying monitor enable on {interface} "
                f"(driver={self._iface_driver(interface) or 'unknown'})…"
            )
            ok_set, set_out = self._enable_monitor(interface)
            out = (out or "") + "\n" + set_out
            if ok_set:
                mon = interface

        if mon and self._discover_monitor_iface(preferred=mon):
            self._helper.run_capture(["ip", "link", "set", mon, "up"])
            self.session.interface = interface
            self.session.monitor_interface = mon
            self._emit(f"Monitor interface: {mon}")
            self._log_iface_diag(mon)
            self._warn_virtualbox_if_needed()
            return True, out, mon

        self._warn_virtualbox_if_needed()
        self._emit(
            "Monitor mode FAILED. For RTL8192EU: reinstall driver from Drivers "
            "(must have CONFIG_WIFI_MONITOR=y). If you are in VirtualBox, "
            "txpower -100 / Invalid argument is common — use bare-metal Kali "
            "or a different USB adapter (e.g. Atheros AR9271)."
        )
        return False, out or "Monitor mode not active", None

    def _warn_virtualbox_if_needed(self) -> None:
        code, out = self._helper.run_capture(["systemd-detect-virt"], timeout=5)
        virt = (out or "").strip().lower()
        if code == 0 and virt and virt not in ("none", ""):
            self._emit(
                f"NOTE: running inside '{virt}'. USB Wi-Fi monitor mode is often "
                "broken in VMs (especially Realtek). Prefer bare metal."
            )
            return
        _c, lsusb = self._helper.run_capture(["lsusb"], timeout=8)
        if re.search(r"VirtualBox|VMware|QEMU", lsusb or "", re.I):
            self._emit(
                "NOTE: VirtualBox/VMware USB device detected — monitor mode may fail."
            )

    def prepare_for_scan(self) -> None:
        """Check-kill + ensure monitor before airodump (iw OR iwconfig)."""
        mon = self.session.monitor_interface
        iface = self.session.interface or mon
        if not mon and not iface:
            raise RuntimeError("Monitor interface not set. Enable monitor mode first.")

        target = iface or mon
        assert target is not None

        self._emit("Preparing interface for scan (check kill + ensure monitor)…")
        self.check_kill()
        self._helper.run_capture(["rfkill", "unblock", "all"])

        still = self._discover_monitor_iface(preferred=target)
        if not still:
            ok, _out, new_mon = self.start_monitor(
                target, auto_check_kill=False, force_reset=True
            )
            if not ok or not new_mon:
                self._warn_virtualbox_if_needed()
                raise RuntimeError(
                    "Could not enable monitor mode. "
                    "Drivers → Install again (8192eu needs CONFIG_WIFI_MONITOR=y). "
                    "Avoid VirtualBox for this adapter if possible."
                )
            still = new_mon

        self._helper.run_capture(["ip", "link", "set", still, "up"])
        self.session.monitor_interface = still
        if not self.session.interface:
            self.session.interface = still
        self._log_iface_diag(still)

    def _log_iface_diag(self, iface: str) -> None:
        _c, iw_out = self._helper.run_capture(["iw", "dev", iface, "info"])
        snippet = (iw_out or "").strip() or "(no iw info)"
        self._emit(f"iw {iface} info:\n{snippet}")
        _c2, iwc = self._helper.run_capture(["iwconfig", iface])
        if iwc.strip():
            self._emit(f"iwconfig {iface}:\n{iwc.strip()}")
        _c3, rf = self._helper.run_capture(["rfkill", "list"])
        if rf and re.search(r"Soft blocked:\s*yes|Hard blocked:\s*yes", rf, re.I):
            self._emit("WARNING: rfkill shows a block — ran unblock; replug if still blocked")
            self._emit(rf.strip())

    def diagnose_empty_scan(self) -> str:
        """Explain why the AP table may be empty."""
        lines: list[str] = []
        path = self.session.scan_csv_path
        if not path:
            lines.append("No scan CSV path set.")
        elif not path.exists():
            lines.append(f"CSV missing: {path} (airodump may have failed to start)")
        else:
            size = path.stat().st_size
            lines.append(f"CSV exists ({size} bytes): {path}")
            try:
                preview = path.read_text(encoding="utf-8", errors="replace")[:400]
                lines.append("CSV preview:\n" + preview)
            except OSError as exc:
                lines.append(f"Could not read CSV: {exc}")

        mon = self.session.monitor_interface
        if mon:
            _c, iw_out = self._helper.run_capture(["iw", "dev", mon, "info"])
            lines.append((iw_out or "").strip() or f"No iw info for {mon}")
            _c2, iwc = self._helper.run_capture(["iwconfig", mon])
            if iwc.strip():
                lines.append(iwc.strip())
            in_mon = self._discover_monitor_iface(preferred=mon) == mon
            if not in_mon:
                lines.append("NOT in monitor mode — that explains empty scans.")

        _c, check = self._helper.run_capture(["airmon-ng", "check"])
        if re.search(r"NetworkManager|wpa_supplicant", check or "", re.I):
            lines.append(
                "NetworkManager/wpa_supplicant still running — they break scanning."
            )

        driver = self._iface_driver(mon) if mon else ""
        if driver:
            lines.append(f"Driver: {driver}")
            if self._uses_ioctl_monitor(mon or ""):
                lines.append(
                    "This driver uses iwconfig for monitor (not iw set type monitor)."
                )

        msg = "\n".join(lines)
        self._emit(msg)
        return msg

    def _discover_monitor_iface(self, preferred: Optional[str] = None) -> Optional[str]:
        """Find an interface already in monitor mode via iwconfig first, then iw."""
        # Prefer iwconfig — rtl8192eu often shows managed in `iw` even when
        # iwconfig Mode:Monitor (or airmon thinks it enabled).
        _c, iwc = self._helper.run_capture(["iwconfig"])
        if preferred and parsers.iface_is_monitor(iwc, preferred):
            return preferred
        ifaces = parsers.parse_wireless_interfaces(iwc)
        for name in ifaces:
            if parsers.iface_is_monitor(iwc, name):
                return name

        code, iw_out = self._helper.run_capture(["iw", "dev"])
        mons = parsers.parse_iw_monitor_interfaces(iw_out) if code == 0 or iw_out else []
        if preferred and preferred in mons:
            return preferred
        if mons:
            return mons[0]

        if preferred:
            guess = f"{preferred}mon" if not preferred.endswith("mon") else preferred
            if guess in ifaces:
                return guess
        for name in ifaces:
            if name.endswith("mon"):
                return name
        return None

    def _enable_monitor(self, interface: str) -> tuple[bool, str]:
        """Enable monitor using the API this driver supports."""
        if self._uses_ioctl_monitor(interface):
            self._emit(
                f"{interface} uses ioctl driver "
                f"({self._iface_driver(interface)}) — using iwconfig, not iw"
            )
            return self._enable_monitor_via_iwconfig(interface)

        ok, out = self._enable_monitor_via_iw(interface)
        if not ok and re.search(r"Operation not supported|not supported", out, re.I):
            self._emit("iw failed — falling back to iwconfig mode monitor")
            return self._enable_monitor_via_iwconfig(interface)
        return ok, out

    def _enable_monitor_via_iwconfig(self, interface: str) -> tuple[bool, str]:
        """Legacy Realtek (8192eu/8188eu): iwconfig mode monitor."""
        logs: list[str] = []

        # Try common orderings — some builds reject mode while down/up differently
        sequences = [
            [
                ["ip", "link", "set", interface, "down"],
                ["iwconfig", interface, "mode", "monitor"],
                ["ip", "link", "set", interface, "up"],
            ],
            [
                ["ip", "link", "set", interface, "up"],
                ["iwconfig", interface, "mode", "monitor"],
            ],
        ]
        for cmds in sequences:
            for cmd in cmds:
                self._emit("Running: " + " ".join(cmd))
                code, out = self._helper.run_capture(cmd)
                chunk = out.strip() or f"(exit {code})"
                logs.append(" ".join(cmd) + " -> " + chunk)
                self._emit(chunk)
            time.sleep(0.4)
            if self._discover_monitor_iface(preferred=interface):
                return True, "\n".join(logs)
            _c, iwc = self._helper.run_capture(["iwconfig", interface])
            if parsers.iface_is_monitor(iwc, interface):
                return True, "\n".join(logs)

        tip = (
            "\nMonitor mode not supported by this 8192eu build "
            "(CONFIG_WIFI_MONITOR was likely n). "
            "Drivers → Install recommended again (rebuilds with monitor=y)."
        )
        return False, "\n".join(logs) + tip

    def _enable_monitor_via_iw(self, interface: str) -> tuple[bool, str]:
        """Set type monitor with iw (mac80211 drivers only)."""
        logs: list[str] = []
        for cmd in (
            ["ip", "link", "set", interface, "down"],
            ["iw", "dev", interface, "set", "type", "monitor"],
            ["ip", "link", "set", interface, "up"],
        ):
            self._emit("Running: " + " ".join(cmd))
            code, out = self._helper.run_capture(cmd)
            chunk = out.strip() or f"(exit {code})"
            logs.append(" ".join(cmd) + " -> " + chunk)
            self._emit(chunk)
            if code != 0 and "set type monitor" in " ".join(cmd):
                return False, "\n".join(logs)

        mon = self._discover_monitor_iface(preferred=interface)
        if mon:
            return True, "\n".join(logs)
        return False, "\n".join(logs) + "\nMonitor mode not confirmed after iw"

    def stop_monitor(self, mon_iface: Optional[str] = None) -> tuple[bool, str]:
        target = mon_iface or self.session.monitor_interface
        if not target:
            return False, "No monitor interface set"
        self._emit(f"Running: airmon-ng stop {target}")
        code, out = self._helper.run_capture(["airmon-ng", "stop", target])
        self._emit(out.strip() or "(no output)")
        restored = parsers.parse_airmon_disabled_iface(out)

        still = self._discover_monitor_iface(preferred=target)
        if still == target:
            self._emit(f"Restoring managed mode on {target}…")
            if self._uses_ioctl_monitor(target):
                for cmd in (
                    ["ip", "link", "set", target, "down"],
                    ["iwconfig", target, "mode", "managed"],
                    ["ip", "link", "set", target, "up"],
                ):
                    c, o = self._helper.run_capture(cmd)
                    self._emit((o.strip() or f"(exit {c})"))
            else:
                for cmd in (
                    ["ip", "link", "set", target, "down"],
                    ["iw", "dev", target, "set", "type", "managed"],
                    ["ip", "link", "set", target, "up"],
                ):
                    c, o = self._helper.run_capture(cmd)
                    self._emit((o.strip() or f"(exit {c})"))
            restored = restored or target

        self.session.monitor_interface = None
        if restored:
            self.session.interface = restored
        elif self.session.interface is None:
            self.session.interface = target
        return True, out

    # ------------------------------------------------------------------- scan
    @property
    def scanning(self) -> bool:
        return self._scan_runner.running

    def start_scan(
        self,
        *,
        on_line: Optional[OnLine] = None,
        on_done: Optional[OnDone] = None,
    ) -> Path:
        self.prepare_for_scan()
        mon = self.session.monitor_interface
        assert mon is not None

        self.stop_scan()
        self.session.reset_scan()

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = self.captures_dir / f"scan_{stamp}"
        self._scan_prefix = prefix
        csv_path = Path(f"{prefix}-01.csv")
        self.session.scan_csv_path = csv_path

        # Full channel hop (2.4 + 5 if supported). Avoid --band filter — some
        # rtl8xxxu builds mishandle it and return zero APs.
        cmd = [
            "airodump-ng",
            "--write-interval",
            "1",
            "-w",
            str(prefix),
            "--output-format",
            "csv",
            mon,
        ]
        self._emit("Starting scan: " + " ".join(cmd))
        self._emit("AP list updates from CSV (airodump TUI spam is hidden).")

        def _line(line: str) -> None:
            # Never flood the GUI with curses escape sequences
            if on_line and parsers.is_useful_airodump_log_line(line):
                on_line(parsers.strip_ansi(line).strip())

        def _done(code: int) -> None:
            self._emit(f"Scan process exited ({code})")
            if on_done:
                on_done(code)

        # Discard most TUI output: still start reader so the pipe doesn't fill
        self._scan_runner.start(cmd, on_line=_line, on_done=_done)
        return csv_path

    def stop_scan(self) -> None:
        if self._scan_runner.running:
            self._emit("Stopping scan...")
            self._scan_runner.stop()

    def refresh_scan_results(self) -> tuple[list[AccessPoint], list[Station]]:
        path = self.session.scan_csv_path
        if not path:
            return [], []
        # airodump may still be writing; retry briefly
        aps, stas = [], []
        for _ in range(3):
            aps, stas = parsers.parse_airodump_csv_file(path)
            if aps or stas:
                break
            time.sleep(0.2)
        self.session.access_points = aps
        self.session.stations = stas
        return aps, stas

    def stations_for_ap(self, bssid: str) -> list[Station]:
        bssid_l = bssid.lower()
        return [
            s
            for s in self.session.stations
            if s.bssid.lower() == bssid_l and s.bssid.lower() != "(not associated)"
        ]

    # ---------------------------------------------------------------- capture
    @property
    def capturing(self) -> bool:
        return self._capture_runner.running

    def start_capture(
        self,
        *,
        on_line: Optional[OnLine] = None,
        on_done: Optional[OnDone] = None,
        on_handshake: Optional[Callable[[], None]] = None,
    ) -> Path:
        self.stop_capture()
        self.session.handshake_ready = False
        self.session.cracked_key = None
        self._handshake_stop_scheduled = False

        self.prepare_for_scan()
        mon = self.session.monitor_interface
        ap = self.session.selected_ap
        if not mon:
            raise RuntimeError("Monitor interface not set")
        if not ap:
            raise RuntimeError("No access point selected")
        channel = (ap.channel or "").strip()
        if not channel or channel == "-1":
            raise RuntimeError("Selected AP has no valid channel")

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_essid = re.sub(r"[^\w\-]+", "_", ap.essid or "unknown")[:32]
        prefix = self.captures_dir / f"cap_{safe_essid}_{stamp}"
        self._capture_prefix = prefix
        self.session.capture_prefix = str(prefix)
        cap_path = Path(f"{prefix}-01.cap")
        self.session.capture_cap_path = cap_path

        cmd = [
            "airodump-ng",
            "--write-interval",
            "1",
            "-c",
            channel,
            "--bssid",
            ap.bssid,
            "-w",
            str(prefix),
            mon,
        ]
        self._emit("Starting capture: " + " ".join(cmd))

        def _line(line: str) -> None:
            clean = parsers.strip_ansi(line).strip()
            if on_line and parsers.is_useful_airodump_log_line(line):
                on_line(clean)
            hs = parsers.handshake_from_airodump_line(clean)
            if hs:
                self._mark_handshake(
                    reason=f"airodump: {hs}",
                    on_handshake=on_handshake,
                    auto_stop=True,
                )

        def _done(code: int) -> None:
            self._emit(f"Capture process exited ({code})")
            if not self.session.handshake_ready:
                if self.probe_handshake(auto_stop=False):
                    if on_handshake:
                        on_handshake()
            if on_done:
                on_done(code)

        self._capture_runner.start(cmd, on_line=_line, on_done=_done)
        return cap_path

    def _mark_handshake(
        self,
        *,
        reason: str,
        on_handshake: Optional[Callable[[], None]] = None,
        auto_stop: bool = True,
    ) -> None:
        first = not self.session.handshake_ready
        self.session.handshake_ready = True
        if first:
            self._emit(f"Handshake detected ({reason})")
            if on_handshake:
                on_handshake()
        if auto_stop:
            self._schedule_auto_stop_capture()

    def _schedule_auto_stop_capture(self) -> None:
        """Stop airodump shortly after handshake so the .cap can flush."""
        if getattr(self, "_handshake_stop_scheduled", False):
            return
        if not self._capture_runner.running:
            return
        self._handshake_stop_scheduled = True
        self._emit("Handshake ready — stopping capture automatically…")

        def _stop_soon() -> None:
            # Give airodump time to flush EAPOL frames to the .cap
            time.sleep(3.5)
            if self._deauth_runner.running:
                self._deauth_runner.stop(force=True)
            if self._capture_runner.running:
                self.stop_capture()
                self._emit("Capture stopped (handshake captured)")

        threading.Thread(target=_stop_soon, daemon=True).start()

    def stop_capture(self) -> None:
        if self._capture_runner.running:
            self._emit("Stopping capture...")
            self._capture_runner.stop()

    def deauth(
        self,
        *,
        count: int = 5,
        on_line: Optional[OnLine] = None,
        on_done: Optional[OnDone] = None,
    ) -> None:
        mon = self.session.monitor_interface
        ap = self.session.selected_ap
        client = self.session.selected_client
        if not mon or not ap:
            raise RuntimeError("Monitor interface and AP required for deauth")

        # Clamp: 0 = continuous (hangs forever); high values flood the UI
        count = max(1, min(int(count), 10))

        cmd = ["aireplay-ng", "-0", str(count), "-a", ap.bssid]
        if client and client.station_mac:
            cmd.extend(["-c", client.station_mac])
        cmd.append(mon)

        self._emit("Deauth: " + " ".join(cmd))
        self._line_n = 0

        def _line(line: str) -> None:
            # Throttle spam — aireplay prints a line per burst of 64 frames
            self._line_n += 1
            n = self._line_n
            if n <= 2 or n % 10 == 0 or "failed" in line.lower() or "error" in line.lower():
                self._emit(line)
                if on_line:
                    on_line(line)

        def _done(code: int) -> None:
            if on_done:
                on_done(code)

        # Hard stop so a stuck aireplay cannot freeze the session
        self._deauth_runner.start(cmd, on_line=_line, on_done=_done, timeout=25.0)

    def probe_handshake(self, *, auto_stop: bool = True) -> bool:
        cap = self.session.capture_cap_path
        if not cap or not cap.exists():
            return False
        code, out = self._helper.run_capture(
            ["aircrack-ng", str(cap)],
            timeout=30,
        )
        ready = parsers.aircrack_reports_handshake(out)
        if ready:
            self._mark_handshake(
                reason="aircrack-ng probe",
                auto_stop=auto_stop and self.capturing,
            )
        return ready

    # ------------------------------------------------------------------- crack
    @property
    def cracking(self) -> bool:
        return self._crack_runner.running

    def start_crack(
        self,
        wordlist: Path,
        *,
        on_line: Optional[OnLine] = None,
        on_done: Optional[Callable[[int, Optional[str]], None]] = None,
    ) -> None:
        cap = self.session.capture_cap_path
        ap = self.session.selected_ap
        if not cap or not cap.exists():
            raise RuntimeError(f"Capture file not found: {cap}")
        if not wordlist.exists():
            raise RuntimeError(f"Wordlist not found: {wordlist}")
        if not ap:
            raise RuntimeError("No AP selected")

        self.session.wordlist_path = wordlist
        self.session.cracked_key = None

        cmd = ["aircrack-ng", "-w", str(wordlist), "-b", ap.bssid, str(cap)]
        self._emit("Cracking: " + " ".join(cmd))

        buffer: list[str] = []

        def _line(line: str) -> None:
            buffer.append(line)
            key = parsers.parse_aircrack_key(line)
            if key:
                self.session.cracked_key = key
                self._emit(f"KEY FOUND: {key}")
            if on_line:
                on_line(line)

        def _done(code: int) -> None:
            joined = "\n".join(buffer)
            if not self.session.cracked_key:
                key = parsers.parse_aircrack_key(joined)
                if key:
                    self.session.cracked_key = key
            self._emit(f"Crack process exited ({code})")
            if on_done:
                on_done(code, self.session.cracked_key)

        self._crack_runner.start(cmd, on_line=_line, on_done=_done)

    def stop_crack(self) -> None:
        if self._crack_runner.running:
            self._emit("Stopping crack...")
            self._crack_runner.stop()

    def tool_hint(self) -> str:
        missing = self.missing_binaries()
        if not missing:
            return ""
        return "Missing tools: " + ", ".join(missing)

    def install_aircrack(
        self,
        *,
        on_line: Optional[OnLine] = None,
        on_done: Optional[OnDone] = None,
    ) -> None:
        """Install aircrack-ng via apt (requires root). Runs in a background thread."""
        if self._installing_tools:
            self._emit("aircrack-ng install already running.")
            return
        if not self.is_root():
            self._emit("Root required to install aircrack-ng. Run via sudo ./run.sh")
            if on_done:
                on_done(1)
            return

        self._installing_tools = True

        def _run() -> None:
            code = 1
            try:
                cmds = [
                    ["apt-get", "update"],
                    ["apt-get", "install", "-y", "aircrack-ng"],
                ]
                for cmd in cmds:
                    self._emit("Running: " + " ".join(cmd))
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    out = (proc.stdout or "") + (proc.stderr or "")
                    for line in out.splitlines():
                        msg = line.rstrip()
                        if msg:
                            self._emit(msg)
                            if on_line:
                                on_line(msg)
                    if proc.returncode != 0:
                        self._emit(f"Command failed ({proc.returncode}): {' '.join(cmd)}")
                        code = proc.returncode
                        return
                missing = self.missing_binaries()
                if missing:
                    self._emit("Install finished but still missing: " + ", ".join(missing))
                    code = 1
                else:
                    self._emit("aircrack-ng tools installed successfully.")
                    code = 0
            except Exception as exc:
                self._emit(f"Install error: {exc}")
                code = 1
            finally:
                self._installing_tools = False
                if on_done:
                    on_done(code)

        threading.Thread(target=_run, daemon=True).start()

    @property
    def installing_tools(self) -> bool:
        return self._installing_tools
