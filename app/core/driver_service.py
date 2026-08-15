"""Detect Wi-Fi chipsets and install Kali monitor/injection drivers."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.core.process_runner import ProcessRunner

OnLine = Callable[[str], None]

# USB vendor prefixes commonly used by Wi-Fi dongles
WIFI_USB_VENDORS = (
    "0bda:",  # Realtek
    "2357:",  # TP-Link
    "148f:",  # Ralink
    "0cf3:",  # Atheros / Qualcomm
    "0b05:",  # ASUS
    "04bb:",  # I-O DATA
    "2001:",  # D-Link
    "0846:",  # Netgear
    "13b1:",  # Linksys
    "7392:",  # Edimax
    "0e8d:",  # MediaTek
    "045e:",  # Microsoft (some)
)

WIFI_USB_KEYWORDS = (
    "wireless",
    "802.11",
    "wlan",
    "wi-fi",
    "wifi",
    "realtek",
    "ralink",
    "atheros",
    "mediatek",
    "tp-link",
    "rtl8",
    "rtl81",
    "rtl88",
)


@dataclass
class DriverProfile:
    """Known chipset → recommended install path."""

    id: str
    label: str
    usb_id_patterns: list[str]
    chipset_keywords: list[str]
    bad_modules: list[str]
    good_module: str
    blacklist_modules: list[str]
    notes: str = ""
    # Install: apt package and/or git DKMS
    apt_package: str = ""
    install_method: str = "apt"  # apt | git_dkms
    git_url: str = ""
    dkms_name: str = ""
    dkms_version: str = "1.0"

    @property
    def install_label(self) -> str:
        if self.install_method == "git_dkms":
            return f"git:{self.dkms_name or self.id}"
        return self.apt_package or "(manual)"


# Profiles ordered by specificity (first match wins)
PROFILES: list[DriverProfile] = [
    DriverProfile(
        id="rtl8192eu",
        label="Realtek RTL8192EU (TP-Link TL-WN823N v2/v3, …)",
        usb_id_patterns=[
            "2357:0109",  # TL-WN823N v2/v3
            "2357:0108",
            "2357:0126",
            "0bda:818b",
            "0bda:818c",
            "2001:3319",
            "0bda:8178",
        ],
        chipset_keywords=["rtl8192eu", "8192eu", "tl-wn823n", "wn823n"],
        bad_modules=["rtl8xxxu"],
        good_module="8192eu",
        blacklist_modules=["rtl8xxxu"],
        install_method="git_dkms",
        # Mange fork ships CONFIG_WIFI_MONITOR=y (clnhub defaults to n → iwconfig fails)
        git_url="https://github.com/Mange/rtl8192eu-linux-driver.git",
        dkms_name="rtl8192eu",
        dkms_version="1.0",
        notes=(
            "Must be built with CONFIG_WIFI_MONITOR=y. Re-run Install if "
            "iwconfig mode monitor returns Invalid argument. "
            "VirtualBox USB passthrough often breaks this stick (txpower -100)."
        ),
    ),
    DriverProfile(
        id="rtl8188eus",
        label="Realtek RTL8188EUS / 8188EU (monitor + injection)",
        usb_id_patterns=["0bda:8179", "0bda:0179", "0bda:8189"],
        chipset_keywords=["rtl8188eus", "rtl8188eu", "rtl8188etv", "8188eu"],
        bad_modules=["rtl8xxxu", "r8188eu"],
        good_module="8188eu",
        apt_package="realtek-rtl8188eus-dkms",
        # Prefer git: Kali apt package is in contrib and often missing / headers mismatch
        install_method="git_dkms",
        blacklist_modules=["r8188eu", "rtl8xxxu"],
        git_url="https://github.com/aircrack-ng/rtl8188eus.git",
        dkms_name="realtek-rtl8188eus",
        dkms_version="5.7.6.1~20200205",
        notes=(
            "Install via aircrack-ng/rtl8188eus DKMS (module 8188eu). "
            "Blacklist rtl8xxxu. Unplug/replug after install."
        ),
    ),
    DriverProfile(
        id="rtl88xxau",
        label="Realtek RTL8812AU / 8814AU / 8821AU (88XXau)",
        usb_id_patterns=[
            "0bda:8812",
            "0bda:881a",
            "0bda:0821",
            "0bda:a811",
            "2357:0101",
            "2357:010d",
            "2357:011e",
            "2604:0012",
        ],
        chipset_keywords=["rtl8812", "rtl8814", "rtl8821", "88xxau", "8812au"],
        bad_modules=[],
        good_module="88XXau",
        apt_package="realtek-rtl88xxau-dkms",
        blacklist_modules=[],
        notes="Preferred for dual-band monitor/injection on Kali.",
    ),
    DriverProfile(
        id="rtl8814au",
        label="Realtek RTL8814AU",
        usb_id_patterns=["0bda:8813", "2357:0106"],
        chipset_keywords=["rtl8814au", "8814au"],
        bad_modules=[],
        good_module="8814au",
        apt_package="realtek-rtl8814au-dkms",
        blacklist_modules=[],
        notes="High-power AC adapter; use Kali DKMS package when available.",
    ),
]


@dataclass
class AdapterInfo:
    iface: str = ""
    driver: str = ""
    chipset: str = ""
    usb: str = ""
    usb_ids: str = ""
    profile: Optional[DriverProfile] = None
    status: str = "unknown"  # ok | needs_driver | unknown
    detail: str = ""
    source: str = ""  # usb | iface | airmon


@dataclass
class DriverReport:
    adapters: list[AdapterInfo] = field(default_factory=list)
    lsusb: str = ""
    airmon: str = ""
    packages_installed: dict[str, bool] = field(default_factory=dict)
    kernel: str = ""
    is_root: bool = False


class DriverService:
    BLACKLIST_PATH = Path("/etc/modprobe.d/wifi-solution-realtek.conf")
    BUILD_DIR = Path("/tmp/wifi-solution-drivers")

    def __init__(self, *, log: Optional[OnLine] = None) -> None:
        self.log = log or (lambda _m: None)
        self._helper = ProcessRunner()
        self._install_runner = ProcessRunner()
        self._installing = False

    @property
    def installing(self) -> bool:
        return self._installing or self._install_runner.running

    def _emit(self, msg: str) -> None:
        self.log(msg)

    def is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def package_installed(self, name: str) -> bool:
        if not name:
            return False
        code, _out = self._helper.run_capture(["dpkg", "-s", name], timeout=8)
        return code == 0

    def module_loaded(self, name: str) -> bool:
        code, out = self._helper.run_capture(["lsmod"], timeout=8)
        if code != 0:
            return False
        return bool(re.search(rf"^{re.escape(name)}\b", out or "", re.M))

    def dkms_installed(self, name: str, version: str = "1.0") -> bool:
        code, out = self._helper.run_capture(["dkms", "status"], timeout=15)
        if code != 0:
            return False
        # rtl8192eu, 1.0, ...: installed
        return bool(
            re.search(
                rf"{re.escape(name)}\s*,\s*{re.escape(version)}.*installed",
                out or "",
                re.I,
            )
        )

    def current_driver(self, iface: str) -> str:
        link = Path(f"/sys/class/net/{iface}/device/driver")
        try:
            if link.exists() or link.is_symlink():
                return link.resolve().name
        except OSError:
            pass
        code, out = self._helper.run_capture(["ethtool", "-i", iface], timeout=5)
        m = re.search(r"^driver:\s*(\S+)", out or "", re.M)
        return m.group(1) if m else ""

    def list_ifaces(self) -> list[str]:
        code, out = self._helper.run_capture(["iw", "dev"], timeout=8)
        names = re.findall(r"Interface\s+(\S+)", out or "")
        if names:
            return sorted(set(names))
        code, out = self._helper.run_capture(["iwconfig"], timeout=8)
        return sorted(set(re.findall(r"^(\S+)\s+IEEE\s+802\.11", out or "", re.M)))

    def _match_profile(self, blob: str) -> Optional[DriverProfile]:
        low = blob.lower()
        for prof in PROFILES:
            for uid in prof.usb_id_patterns:
                if uid.lower() in low:
                    return prof
            for kw in prof.chipset_keywords:
                if kw.lower() in low:
                    return prof
        return None

    @staticmethod
    def _parse_usb_id(line: str) -> str:
        m = re.search(r"ID\s+([0-9a-fA-F]{4}:[0-9a-fA-F]{4})", line)
        return m.group(1).lower() if m else ""

    def parse_wireless_usb_devices(self, lsusb: str) -> list[dict[str, str]]:
        """Return every likely Wi-Fi USB device from lsusb (generic)."""
        found: list[dict[str, str]] = []
        for line in (lsusb or "").splitlines():
            low = line.lower()
            vid = any(v in low for v in WIFI_USB_VENDORS)
            kw = any(k in low for k in WIFI_USB_KEYWORDS)
            # Skip hubs / virtualbox tablet noise unless keyword matches strongly
            if "root hub" in low or "virtualbox" in low:
                continue
            if not (vid or kw):
                continue
            # Vendor-only without wireless keyword: still keep Realtek/TP-Link/Ralink NICs
            if vid and not kw:
                # Keep known Wi-Fi vendors even if description is sparse
                if not any(
                    v in low
                    for v in ("0bda:", "2357:", "148f:", "0cf3:", "2001:", "0e8d:")
                ):
                    continue
            usb_id = self._parse_usb_id(line)
            found.append({"usb": line.strip(), "usb_ids": usb_id, "desc": line.strip()})
        return found

    def verify(self) -> DriverReport:
        """List all wireless USB + ifaces; recommend drivers when known."""
        report = DriverReport(
            kernel=os.uname().release if hasattr(os, "uname") else "",
            is_root=self.is_root(),
        )
        self._emit("Scanning USB Wi-Fi devices and wireless interfaces…")
        _c, report.lsusb = self._helper.run_capture(["lsusb"], timeout=10)
        _c, report.airmon = self._helper.run_capture(["airmon-ng"], timeout=12)
        if _c == 124:
            self._emit("airmon-ng timed out — continuing with lsusb/iw")
            report.airmon = report.airmon or "(airmon-ng timed out)"

        for pkg in {p.apt_package for p in PROFILES if p.apt_package}:
            report.packages_installed[pkg] = self.package_installed(pkg)

        usb_devs = self.parse_wireless_usb_devices(report.lsusb)
        airmon_rows = self._parse_airmon_table(report.airmon)
        ifaces = self.list_ifaces()

        # Index ifaces by driver for later merge
        iface_driver = {iface: self.current_driver(iface) for iface in ifaces}

        # 1) Always show every wireless USB device
        used_usb_ids: set[str] = set()
        for dev in usb_devs:
            usb_id = dev["usb_ids"]
            used_usb_ids.add(usb_id)
            blob = " ".join([dev["usb"], report.airmon, " ".join(ifaces)])
            prof = self._match_profile(blob)
            # Try to pair with an iface that shares this driver/chip family
            paired_iface = ""
            paired_driver = ""
            for iface, drv in iface_driver.items():
                if prof and drv.lower() in (
                    [m.lower() for m in prof.bad_modules]
                    + [prof.good_module.lower(), "rtl8xxxu"]
                ):
                    paired_iface = iface
                    paired_driver = drv
                    break
            if not paired_iface and len(ifaces) == 1:
                paired_iface = ifaces[0]
                paired_driver = iface_driver.get(paired_iface, "")

            info = AdapterInfo(
                iface=paired_iface or "(no iface yet)",
                driver=paired_driver or "",
                chipset=(prof.label if prof else self._chipset_from_usb(dev["usb"])),
                usb=dev["usb"],
                usb_ids=usb_id,
                profile=prof,
                source="usb",
            )
            self._evaluate(info)
            report.adapters.append(info)

        # 2) Airmon rows not already covered
        seen_ifaces = {a.iface for a in report.adapters if a.iface and not a.iface.startswith("(")}
        for row in airmon_rows:
            iface = row.get("iface", "")
            if not iface or iface in seen_ifaces:
                continue
            seen_ifaces.add(iface)
            chipset = row.get("chipset", "")
            driver = row.get("driver") or iface_driver.get(iface, "")
            blob = " ".join([chipset, driver, report.lsusb])
            prof = self._match_profile(blob)
            info = AdapterInfo(
                iface=iface,
                driver=driver,
                chipset=chipset or (prof.label if prof else ""),
                usb=self._guess_usb_line(chipset or driver, report.lsusb),
                usb_ids=self._parse_usb_id(self._guess_usb_line(chipset or driver, report.lsusb)),
                profile=prof,
                source="airmon",
            )
            self._evaluate(info)
            report.adapters.append(info)

        # 3) Remaining iw ifaces
        for iface in ifaces:
            if iface in seen_ifaces:
                continue
            driver = iface_driver.get(iface, "")
            blob = " ".join([iface, driver, report.lsusb])
            prof = self._match_profile(blob)
            info = AdapterInfo(
                iface=iface,
                driver=driver,
                chipset=prof.label if prof else "",
                usb=self._guess_usb_line(driver, report.lsusb),
                profile=prof,
                source="iface",
            )
            self._evaluate(info)
            report.adapters.append(info)

        self._emit(f"Verify done — {len(report.adapters)} device(s)")
        return report

    @staticmethod
    def _chipset_from_usb(usb_line: str) -> str:
        # "Bus … ID 2357:0109 TP-Link TL-WN823N v2/v3 [Realtek RTL8192EU]"
        m = re.search(r"ID\s+[0-9a-fA-F:]+\s+(.+)$", usb_line)
        return (m.group(1).strip() if m else usb_line)[:80]

    def _evaluate(self, info: AdapterInfo) -> None:
        prof = info.profile
        if not prof:
            info.status = "unknown"
            info.detail = (
                "USB Wi-Fi detected, but no automatic driver recipe for this ID yet. "
                "You can still use Interface/Monitor if the kernel driver works. "
                "For Realtek sticks that scan 0 APs, a dedicated DKMS driver is usually required."
            )
            return

        good_loaded = self.module_loaded(prof.good_module) or (
            info.driver.lower() == prof.good_module.lower()
        )
        bad_loaded = info.driver.lower() in [m.lower() for m in prof.bad_modules]

        if prof.install_method == "git_dkms":
            dkms_ok = self.dkms_installed(prof.dkms_name or prof.id, prof.dkms_version)
            if good_loaded and not bad_loaded:
                info.status = "ok"
                info.detail = (
                    f"Using {info.driver or prof.good_module} — looks good for monitor/injection."
                )
            elif bad_loaded or not good_loaded:
                info.status = "needs_driver"
                info.detail = (
                    f"Current driver '{info.driver or 'none'}' is not ideal. "
                    f"Install {prof.install_label} (module {prof.good_module}). "
                    f"DKMS installed={dkms_ok}. {prof.notes}"
                )
            else:
                info.status = "ok"
                info.detail = "Profile matched; driver appears usable."
            return

        pkg_ok = self.package_installed(prof.apt_package)
        if good_loaded and not bad_loaded and pkg_ok:
            info.status = "ok"
            info.detail = (
                f"Using {info.driver or prof.good_module} — looks good for monitor/injection."
            )
        elif bad_loaded:
            info.status = "needs_driver"
            info.detail = (
                f"Driver '{info.driver}' is known-bad for this chipset. "
                f"Install {prof.apt_package} (module {prof.good_module}). {prof.notes}"
            )
        elif not pkg_ok:
            info.status = "needs_driver"
            info.detail = (
                f"Recommended package not installed: {prof.apt_package}. {prof.notes}"
            )
        elif not good_loaded:
            info.status = "needs_driver"
            info.detail = (
                f"Package may be installed but module '{prof.good_module}' is not loaded "
                f"(current: {info.driver or 'unknown'}). Blacklist stock drivers and reload."
            )
        else:
            info.status = "ok"
            info.detail = "Profile matched; driver appears usable."

    def _parse_airmon_table(self, text: str) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for line in (text or "").splitlines():
            parts = re.split(r"\t+|\s{2,}", line.strip())
            if len(parts) < 3:
                continue
            phy = parts[0].strip()
            if not phy.lower().startswith("phy"):
                continue
            # airmon-ng header: "PHY  Interface  Driver  Chipset"
            if phy.upper() == "PHY" or parts[1].strip().lower() == "interface":
                continue
            iface = parts[1].strip() if len(parts) > 1 else ""
            driver = parts[2].strip() if len(parts) > 2 else ""
            if not iface or iface.lower() in ("interface", "driver", "chipset"):
                continue
            rows.append(
                {
                    "phy": phy,
                    "iface": iface,
                    "driver": driver,
                    "chipset": " ".join(parts[3:]).strip() if len(parts) > 3 else "",
                }
            )
        return rows

    def _guess_usb_line(self, hint: str, lsusb: str) -> str:
        low_hint = (hint or "").lower()
        for line in (lsusb or "").splitlines():
            low = line.lower()
            if any(k in low for k in WIFI_USB_KEYWORDS) or any(
                v in low for v in WIFI_USB_VENDORS
            ):
                if not hint or any(x in low for x in low_hint.split()[:3] if len(x) > 3):
                    return line.strip()
        for line in (lsusb or "").splitlines():
            if any(v in line.lower() for v in ("0bda:", "2357:", "148f:", "0cf3:")):
                return line.strip()
        return ""

    def ensure_blacklist(self, modules: list[str]) -> None:
        if not modules:
            return
        existing = ""
        if self.BLACKLIST_PATH.exists():
            existing = self.BLACKLIST_PATH.read_text(encoding="utf-8", errors="replace")
        lines = existing.splitlines()
        changed = False
        for mod in modules:
            entry = f"blacklist {mod}"
            if entry not in lines:
                lines.append(entry)
                changed = True
        if changed or not self.BLACKLIST_PATH.exists():
            self.BLACKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.BLACKLIST_PATH.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
            self._emit(f"Wrote blacklist: {self.BLACKLIST_PATH}")

    def reload_modules(self, profile: DriverProfile) -> None:
        for mod in profile.bad_modules + [profile.good_module]:
            self._emit(f"rmmod {mod} (ignore errors)…")
            self._helper.run_capture(["rmmod", mod], timeout=20)
        self._emit(f"modprobe {profile.good_module}")
        code, out = self._helper.run_capture(["modprobe", profile.good_module], timeout=30)
        self._emit((out or "").strip() or f"modprobe exit {code}")

    def _run_logged(
        self,
        cmd: list[str],
        *,
        on_line: Optional[OnLine],
        cwd: Optional[str] = None,
    ) -> int:
        self._emit("Running: " + " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        out = (proc.stdout or "") + (proc.stderr or "")
        for line in out.splitlines():
            msg = line.rstrip()
            if msg:
                self._emit(msg)
                if on_line:
                    on_line(msg)
        return proc.returncode

    def install_profile(
        self,
        profile: DriverProfile,
        *,
        on_line: Optional[OnLine] = None,
        on_done: Optional[Callable[[int], None]] = None,
    ) -> None:
        if self.installing:
            self._emit("Install already running.")
            return
        if not self.is_root():
            self._emit("Root required. Run via ./run.sh")
            if on_done:
                on_done(1)
            return

        self._installing = True

        def _run() -> None:
            code = 1
            try:
                code = self._install_best(profile, on_line=on_line)
                if code == 0:
                    self.ensure_blacklist(profile.blacklist_modules)
                    self.reload_modules(profile)
                    rebound = self.rebind_usb_ids(profile.usb_id_patterns)
                    if rebound:
                        self._emit(f"USB rebind attempted for: {', '.join(rebound)}")
                    self._emit(
                        f"Install finished ({profile.install_label}). "
                        "If still no wlan iface: unplug/replug the adapter "
                        "(VirtualBox: Devices → USB → re-attach), then Verify."
                    )
            except Exception as exc:
                self._emit(f"Install error: {exc}")
                code = 1
            finally:
                self._installing = False
                if on_done:
                    on_done(code)

        threading.Thread(target=_run, daemon=True).start()

    def install_profile_blocking(
        self,
        profile: DriverProfile,
        *,
        on_line: Optional[OnLine] = None,
    ) -> int:
        """Install on the current thread (for Bring-up / automation)."""
        if self.installing:
            self._emit("Install already running.")
            return 1
        if not self.is_root():
            self._emit("Root required. Run via ./run.sh")
            return 1
        self._installing = True
        code = 1
        try:
            code = self._install_best(profile, on_line=on_line)
            if code == 0:
                self.ensure_blacklist(profile.blacklist_modules)
                self.reload_modules(profile)
                rebound = self.rebind_usb_ids(profile.usb_id_patterns)
                if rebound:
                    self._emit(f"USB rebind attempted for: {', '.join(rebound)}")
                self._emit(f"Install finished ({profile.install_label}).")
        except Exception as exc:
            self._emit(f"Install error: {exc}")
            code = 1
        finally:
            self._installing = False
        return code

    def _install_best(
        self, profile: DriverProfile, *, on_line: Optional[OnLine]
    ) -> int:
        """Try preferred method, then the other if both apt + git are configured."""
        prefer_git = profile.install_method == "git_dkms" and bool(profile.git_url)
        if prefer_git:
            self._emit(f"Installing via git DKMS: {profile.git_url}")
            code = self._install_git_dkms(profile, on_line=on_line)
            if code == 0:
                return 0
            if profile.apt_package:
                self._emit("git DKMS failed — trying apt package…")
                return self._install_apt(profile, on_line=on_line)
            return code

        code = self._install_apt(profile, on_line=on_line)
        if code == 0:
            return 0
        if profile.git_url:
            self._emit(
                f"apt install failed ({code}) — trying git DKMS "
                f"({profile.git_url})…"
            )
            return self._install_git_dkms(profile, on_line=on_line)
        return code

    def profile_for_usb_blob(self, blob: str) -> Optional[DriverProfile]:
        return self._match_profile(blob)

    def rebind_usb_ids(self, usb_id_patterns: list[str]) -> list[str]:
        """Soft re-plug: unbind/bind matching USB devices under /sys."""
        rebound: list[str] = []
        usb_root = Path("/sys/bus/usb/devices")
        if not usb_root.is_dir():
            return rebound
        wanted = {p.lower() for p in usb_id_patterns}
        try:
            for dev in usb_root.iterdir():
                vend = dev / "idVendor"
                prod = dev / "idProduct"
                if not vend.exists() or not prod.exists():
                    continue
                try:
                    uid = f"{vend.read_text().strip()}:{prod.read_text().strip()}".lower()
                except OSError:
                    continue
                if uid not in wanted:
                    continue
                name = dev.name  # e.g. 1-2
                unbind = Path("/sys/bus/usb/drivers/usb/unbind")
                bind = Path("/sys/bus/usb/drivers/usb/bind")
                try:
                    if unbind.exists():
                        unbind.write_text(name)
                        self._emit(f"USB unbind {name} ({uid})")
                    time.sleep(1.0)
                    if bind.exists():
                        bind.write_text(name)
                        self._emit(f"USB bind {name} ({uid})")
                    rebound.append(f"{name}/{uid}")
                except OSError as exc:
                    self._emit(f"USB rebind {name} failed: {exc}")
        except OSError as exc:
            self._emit(f"USB rebind scan failed: {exc}")
        return rebound

    def _install_apt(
        self, profile: DriverProfile, *, on_line: Optional[OnLine]
    ) -> int:
        # Package may live in Kali contrib — make sure apt can see it
        self._ensure_package_visible(profile.apt_package, on_line=on_line)
        self._apt_update_soft(on_line=on_line)
        code = self._install_build_deps(on_line=on_line)
        if code != 0:
            return code
        code = self._run_logged(
            ["apt-get", "install", "-y", profile.apt_package],
            on_line=on_line,
        )
        if code != 0:
            self._emit(f"Command failed ({code}): apt-get install {profile.apt_package}")
            self._emit(
                "Hint: enable Kali contrib (main contrib non-free non-free-firmware)."
            )
        return code

    def _apt_update_soft(self, *, on_line: Optional[OnLine]) -> None:
        code = self._run_logged(["apt-get", "update"], on_line=on_line)
        if code != 0:
            self._emit(f"apt-get update failed ({code}) — continuing with cache")

    def _install_build_deps(self, *, on_line: Optional[OnLine]) -> int:
        kernel = os.uname().release
        # Exact headers often missing after a kernel upgrade; also try metapackage
        pkgs = [
            "dkms",
            "build-essential",
            "git",
            "bc",
            f"linux-headers-{kernel}",
            "linux-headers-amd64",
        ]
        code = self._run_logged(
            ["apt-get", "install", "-y", *pkgs],
            on_line=on_line,
        )
        if code == 0:
            return 0
        self._emit(
            f"Full headers install failed ({code}); retrying without exact "
            f"linux-headers-{kernel}…"
        )
        return self._run_logged(
            [
                "apt-get",
                "install",
                "-y",
                "dkms",
                "build-essential",
                "git",
                "bc",
                "linux-headers-amd64",
            ],
            on_line=on_line,
        )

    def _package_candidate_available(self, package: str) -> bool:
        if not package:
            return False
        code, out = self._helper.run_capture(
            ["apt-cache", "policy", package], timeout=15
        )
        if code != 0 or not out:
            return False
        # Look at Candidate line specifically
        for line in out.splitlines():
            if line.strip().startswith("Candidate:"):
                cand = line.split(":", 1)[-1].strip()
                return bool(cand) and cand != "(none)"
        return False

    def _ensure_package_visible(
        self, package: str, *, on_line: Optional[OnLine]
    ) -> None:
        if not package:
            return
        if self._package_candidate_available(package):
            return
        self._emit(
            f"Package '{package}' not visible to apt — enabling contrib in apt sources…"
        )
        source_files: list[Path] = []
        main = Path("/etc/apt/sources.list")
        if main.exists():
            source_files.append(main)
        d = Path("/etc/apt/sources.list.d")
        if d.is_dir():
            source_files.extend(sorted(d.glob("*.list")))
            source_files.extend(sorted(d.glob("*.sources")))

        changed_any = False
        for sources in source_files:
            try:
                raw = sources.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            new_raw, changed = self._inject_contrib(raw)
            if not changed:
                continue
            try:
                sources.write_text(new_raw, encoding="utf-8")
                self._emit(f"Updated {sources} to include contrib/non-free")
                if on_line:
                    on_line(f"Updated {sources} to include contrib/non-free")
                changed_any = True
            except OSError as exc:
                self._emit(f"Could not update {sources}: {exc}")
        if not changed_any:
            self._emit(
                "Could not auto-enable contrib. Edit apt sources to include: "
                "main contrib non-free non-free-firmware"
            )

    @staticmethod
    def _inject_contrib(raw: str) -> tuple[str, bool]:
        changed = False
        lines = raw.splitlines()
        new_lines: list[str] = []
        for line in lines:
            stripped = line.strip()
            # Classic one-line deb entries
            if stripped.startswith("deb ") and "kali" in stripped.lower():
                if "contrib" not in stripped:
                    line = line.rstrip() + " contrib"
                    changed = True
                if "non-free" not in stripped:
                    line = line.rstrip() + " non-free non-free-firmware"
                    changed = True
            # deb822 .sources files
            elif stripped.lower().startswith("components:"):
                lower = stripped.lower()
                if "contrib" not in lower or "non-free" not in lower:
                    comps = stripped.split(":", 1)[-1].strip().split()
                    for c in ("main", "contrib", "non-free", "non-free-firmware"):
                        if c not in comps:
                            comps.append(c)
                            changed = True
                    line = "Components: " + " ".join(comps)
            new_lines.append(line)
        if not changed:
            return raw, False
        return "\n".join(new_lines) + "\n", True

    def _install_git_dkms(
        self, profile: DriverProfile, *, on_line: Optional[OnLine]
    ) -> int:
        name = profile.dkms_name or profile.id
        ver = profile.dkms_version or "1.0"
        src = self.BUILD_DIR / name

        self._apt_update_soft(on_line=on_line)
        code = self._install_build_deps(on_line=on_line)
        if code != 0:
            self._emit(
                "Cannot install build deps / kernel headers. "
                "Try: apt install dkms build-essential git linux-headers-amd64"
            )
            return code

        self.BUILD_DIR.mkdir(parents=True, exist_ok=True)
        if src.exists():
            shutil.rmtree(src, ignore_errors=True)

        code = self._run_logged(
            ["git", "clone", "--depth", "1", profile.git_url, str(src)],
            on_line=on_line,
        )
        if code != 0:
            return code

        # Prefer names from upstream dkms.conf when present
        name, ver = self._read_dkms_identity(src, name, ver)
        self._emit(f"DKMS identity: {name}/{ver}")

        # Realtek out-of-tree drivers often ship with monitor disabled
        self._enable_wifi_monitor_flag(src)

        # Prefer upstream install script when present
        for script in ("dkms-install.sh", "install.sh", "install_wifi.sh"):
            path = src / script
            if path.exists():
                path.chmod(path.stat().st_mode | 0o111)
                code = self._run_logged(
                    ["bash", str(path)], on_line=on_line, cwd=str(src)
                )
                if code == 0:
                    return 0
                self._emit(f"{script} failed ({code}); trying manual dkms…")

        # Manual DKMS
        self._run_logged(
            ["dkms", "remove", f"{name}/{ver}", "--all"],
            on_line=on_line,
        )
        dest = Path(f"/usr/src/{name}-{ver}")
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(src, dest)
        for cmd in (
            ["dkms", "add", "-m", name, "-v", ver],
            ["dkms", "install", "-m", name, "-v", ver],
        ):
            code = self._run_logged(cmd, on_line=on_line)
            if code != 0:
                return code
        return 0

    @staticmethod
    def _read_dkms_identity(
        src: Path, default_name: str, default_ver: str
    ) -> tuple[str, str]:
        conf = src / "dkms.conf"
        name, ver = default_name, default_ver
        if not conf.exists():
            return name, ver
        try:
            text = conf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return name, ver
        m = re.search(r'PACKAGE_NAME\s*=\s*"([^"]+)"', text)
        if m:
            name = m.group(1)
        m = re.search(r'PACKAGE_VERSION\s*=\s*"([^"]+)"', text)
        if m:
            ver = m.group(1)
        return name, ver

    def _enable_wifi_monitor_flag(self, src: Path) -> None:
        """Force CONFIG_WIFI_MONITOR=y so iwconfig mode monitor works."""
        patched = 0
        for makefile in src.rglob("Makefile"):
            try:
                text = makefile.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "CONFIG_WIFI_MONITOR" not in text:
                continue
            new = re.sub(
                r"^(CONFIG_WIFI_MONITOR\s*=\s*)n\s*$",
                r"\1y",
                text,
                flags=re.MULTILINE,
            )
            if new != text:
                makefile.write_text(new, encoding="utf-8")
                self._emit(f"Patched CONFIG_WIFI_MONITOR=y in {makefile}")
                patched += 1
        if patched == 0:
            self._emit("Note: no CONFIG_WIFI_MONITOR=n found to patch (may already be y)")

    def profiles_for_report(self, report: DriverReport) -> list[DriverProfile]:
        found: list[DriverProfile] = []
        seen: set[str] = set()
        for ad in report.adapters:
            if ad.profile and ad.profile.id not in seen:
                found.append(ad.profile)
                seen.add(ad.profile.id)
        return found
