"""Parsers for airodump CSV, airmon output, and aircrack results."""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Optional

from app.core.state import AccessPoint, Station


IWCONFIG_IFACE_RE = re.compile(r"^(\S+)\s+IEEE\s+802\.11", re.MULTILINE)
# Matches: "enabled", "vif enabled", "already enabled", etc.
AIRMON_ENABLED_RE = re.compile(
    r"monitor mode (?:vif )?(?:already )?enabled"
    r"(?: for (\[phy\d+\])?(\S+))? on\s+(\S+)",
    re.IGNORECASE,
)
# Some drivers only print "(monitor mode enabled)" with no "on <iface>"
AIRMON_ENABLED_BARE_RE = re.compile(
    r"monitor mode (?:vif )?(?:already )?enabled(?!\s+for)",
    re.IGNORECASE,
)
AIRMON_DISABLED_RE = re.compile(
    r"monitor mode (?:vif )?(?:already )?disabled"
    r"(?: for (\[phy\d+\])?(\S+))? on\s+(\S+)",
    re.IGNORECASE,
)
IW_DEV_BLOCK_RE = re.compile(
    r"(?:^|\n)[ \t]*Interface\s+(\S+)(.*?)(?=(?:\n[ \t]*Interface\s+)|\Z)",
    re.IGNORECASE | re.DOTALL,
)
ANSI_ESCAPE_RE = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)"
)
HANDSHAKE_LINE_RE = re.compile(r"WPA handshake:\s*([0-9A-Fa-f:]{17})", re.IGNORECASE)
AIRCRACK_KEY_RE = re.compile(
    r"KEY FOUND!\s*\[\s*(.+?)\s*\]",
    re.IGNORECASE,
)
AIRCRACK_HANDSHAKE_COUNT_RE = re.compile(
    r"(\d+)\s+handshake",
    re.IGNORECASE,
)
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def parse_wireless_interfaces(iwconfig_output: str) -> list[str]:
    """Return wireless interface names from `iwconfig` output."""
    found = IWCONFIG_IFACE_RE.findall(iwconfig_output)
    # Also catch interfaces that show "no wireless extensions" skip;
    # iwconfig lists wireless ones with IEEE 802.11.
    return sorted(set(found))


def parse_iw_interfaces(iw_dev_output: str) -> list[str]:
    """Return all interface names from `iw dev` output."""
    return sorted(
        {
            m.group(1).strip()
            for m in IW_DEV_BLOCK_RE.finditer(iw_dev_output or "")
            if m.group(1).strip()
        }
    )


def parse_ip_link_wireless_hint(ip_link_output: str) -> list[str]:
    """Fallback: interfaces whose name looks like wifi (wlan*, wlp*, wlx*)."""
    names: list[str] = []
    for line in ip_link_output.splitlines():
        # e.g. "3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
        m = re.match(r"^\d+:\s+([^:@]+)", line.strip())
        if not m:
            continue
        name = m.group(1)
        lower = name.lower()
        if lower.startswith(("wlan", "wlp", "wlx", "wifi")) or lower.endswith("mon"):
            names.append(name)
    return sorted(set(names))


def _strip_phy_prefix(name: str) -> str:
    """Convert '[phy0]wlan0mon' -> 'wlan0mon'."""
    name = name.strip().rstrip(")")
    name = name.split()[0]
    m = re.match(r"\[phy\d+\](.+)", name, re.IGNORECASE)
    if m:
        return m.group(1)
    return name


def _is_plausible_iface(name: str) -> bool:
    """Reject airmon quirks like printing ifindex '10' instead of a name."""
    if not name:
        return False
    if name.isdigit():
        return False
    if len(name) > 64:
        return False
    return bool(re.match(r"^[A-Za-z][\w.\-]*$", name))


def _pick_airmon_iface(match: re.Match[str]) -> Optional[str]:
    """
    airmon groups: (phy_prefix_optional, for_name, on_name)
    Prefer a valid 'on' name; else the 'for' source interface.
    """
    for_name = _strip_phy_prefix(match.group(2) or "")
    on_raw = match.group(3) or ""
    on_name = _strip_phy_prefix(on_raw)
    if _is_plausible_iface(on_name):
        return on_name
    if _is_plausible_iface(for_name):
        # Some drivers/airmon builds enable monitor on the same iface
        # and print ifindex after 'on' (e.g. on [phy0]10).
        return for_name
    return None


def parse_airmon_monitor_iface(airmon_output: str) -> Optional[str]:
    """Extract monitor interface name from airmon-ng start output."""
    m = AIRMON_ENABLED_RE.search(airmon_output)
    if m:
        return _pick_airmon_iface(m)
    # Bare "monitor mode enabled" — caller should fall back to preferred iface
    if AIRMON_ENABLED_BARE_RE.search(airmon_output):
        return None
    return None


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def is_useful_airodump_log_line(line: str) -> bool:
    """Filter airodump curses/TUI spam; keep handshake and quit notices."""
    clean = strip_ansi(line).strip()
    if not clean:
        return False
    lower = clean.lower()
    if "wpa handshake" in lower:
        return True
    if lower.startswith("quitting"):
        return True
    if "failed" in lower or "error" in lower or "no such device" in lower:
        return True
    return False


def parse_airmon_disabled_iface(airmon_output: str) -> Optional[str]:
    m = AIRMON_DISABLED_RE.search(airmon_output)
    if not m:
        return None
    return _pick_airmon_iface(m)


def parse_iw_monitor_interfaces(iw_dev_output: str) -> list[str]:
    """Return interface names that are type monitor from `iw dev` output."""
    found: list[str] = []
    for m in IW_DEV_BLOCK_RE.finditer(iw_dev_output):
        name = m.group(1).strip()
        body = m.group(2)
        if re.search(r"^\s*type\s+monitor\b", body, re.IGNORECASE | re.MULTILINE):
            found.append(name)
    return found


def iface_is_monitor(iwconfig_or_iw_output: str, iface: str) -> bool:
    """Heuristic: True if output indicates monitor mode for iface."""
    # iwconfig: "Mode:Monitor"
    block = re.search(
        rf"^{re.escape(iface)}\s+.*?(?=^\S|\Z)",
        iwconfig_or_iw_output,
        re.MULTILINE | re.DOTALL,
    )
    if block and re.search(r"Mode:\s*Monitor", block.group(0), re.IGNORECASE):
        return True
    # iw dev style
    return iface in parse_iw_monitor_interfaces(iwconfig_or_iw_output)


def _clean(cell: Optional[str]) -> str:
    return (cell or "").strip()


def parse_airodump_csv(text: str) -> tuple[list[AccessPoint], list[Station]]:
    """Parse airodump-ng CSV (AP section then Station section)."""
    # Normalize Windows/Unix newlines; airodump uses blank line between sections.
    raw = text.replace("\r\n", "\n").replace("\r", "\n")
    # Split on empty line that precedes "Station MAC"
    parts = re.split(r"\n\s*\n", raw.strip(), maxsplit=1)
    ap_blob = parts[0] if parts else ""
    sta_blob = parts[1] if len(parts) > 1 else ""

    access_points: list[AccessPoint] = []
    stations: list[Station] = []

    # AP section
    ap_reader = csv.reader(io.StringIO(ap_blob))
    ap_rows = list(ap_reader)
    if ap_rows:
        # Skip header if present
        start = 1 if ap_rows and "BSSID" in "".join(ap_rows[0]).upper() else 0
        for row in ap_rows[start:]:
            if len(row) < 14:
                continue
            bssid = _clean(row[0])
            if not MAC_RE.match(bssid):
                continue
            access_points.append(
                AccessPoint(
                    bssid=bssid,
                    first_seen=_clean(row[1]) if len(row) > 1 else "",
                    last_seen=_clean(row[2]) if len(row) > 2 else "",
                    channel=_clean(row[3]) if len(row) > 3 else "",
                    speed=_clean(row[4]) if len(row) > 4 else "",
                    privacy=_clean(row[5]) if len(row) > 5 else "",
                    cipher=_clean(row[6]) if len(row) > 6 else "",
                    auth=_clean(row[7]) if len(row) > 7 else "",
                    power=_clean(row[8]) if len(row) > 8 else "",
                    beacons=_clean(row[9]) if len(row) > 9 else "",
                    iv=_clean(row[10]) if len(row) > 10 else "",
                    lan_ip=_clean(row[11]) if len(row) > 11 else "",
                    id_length=_clean(row[12]) if len(row) > 12 else "",
                    essid=_clean(row[13]) if len(row) > 13 else "",
                    key=_clean(row[14]) if len(row) > 14 else "",
                )
            )

    # Station section
    if sta_blob:
        # May still include header line "Station MAC, ..."
        sta_reader = csv.reader(io.StringIO(sta_blob.strip()))
        sta_rows = list(sta_reader)
        start = 1 if sta_rows and "STATION" in "".join(sta_rows[0]).upper() else 0
        for row in sta_rows[start:]:
            if len(row) < 6:
                continue
            mac = _clean(row[0])
            if not MAC_RE.match(mac):
                continue
            stations.append(
                Station(
                    station_mac=mac,
                    first_seen=_clean(row[1]) if len(row) > 1 else "",
                    last_seen=_clean(row[2]) if len(row) > 2 else "",
                    power=_clean(row[3]) if len(row) > 3 else "",
                    packets=_clean(row[4]) if len(row) > 4 else "",
                    bssid=_clean(row[5]) if len(row) > 5 else "",
                    probed_essids=_clean(",".join(row[6:])) if len(row) > 6 else "",
                )
            )

    return access_points, stations


def parse_airodump_csv_file(path: Path) -> tuple[list[AccessPoint], list[Station]]:
    if not path.exists():
        return [], []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], []
    return parse_airodump_csv(text)


def handshake_from_airodump_line(line: str) -> Optional[str]:
    m = HANDSHAKE_LINE_RE.search(line)
    return m.group(1) if m else None


def parse_aircrack_key(output: str) -> Optional[str]:
    m = AIRCRACK_KEY_RE.search(output)
    return m.group(1).strip() if m else None


def aircrack_reports_handshake(output: str) -> bool:
    """True if aircrack-ng sees at least one handshake in the cap."""
    # Common phrases: "1 handshake", "Opening ...", "No networks found"
    if re.search(r"No networks found", output, re.IGNORECASE):
        return False
    m = AIRCRACK_HANDSHAKE_COUNT_RE.search(output)
    if m and int(m.group(1)) >= 1:
        return True
    if re.search(r"handshake", output, re.IGNORECASE) and not re.search(
        r"0 handshake", output, re.IGNORECASE
    ):
        # Heuristic: presence of handshake wording without zero
        if re.search(r"[1-9]\d*\s+handshake", output, re.IGNORECASE):
            return True
    return False


def which_missing(binaries: list[str]) -> list[str]:
    """Return names of binaries not found on PATH (uses `command -v` style via shutil)."""
    import shutil

    return [b for b in binaries if shutil.which(b) is None]
