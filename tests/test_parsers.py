"""Unit tests for parsers (no aircrack-ng required)."""

from __future__ import annotations

import unittest

from app.core.parsers import (
    aircrack_reports_handshake,
    handshake_from_airodump_line,
    parse_aircrack_key,
    parse_airmon_monitor_iface,
    parse_airodump_csv,
    parse_wireless_interfaces,
)


SAMPLE_CSV = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 6, 54, WPA2, CCMP, PSK, -45, 10, 0, 0.0.0.0, 4, Test, 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2024-01-01 00:00:30, 2024-01-01 00:01:00, -60, 12, AA:BB:CC:DD:EE:FF,
"""


class ParserTests(unittest.TestCase):
    def test_iwconfig_ifaces(self) -> None:
        out = """wlan0     IEEE 802.11  ESSID:off/any
eth0      no wireless extensions.
"""
        self.assertEqual(parse_wireless_interfaces(out), ["wlan0"])

    def test_iw_dev_ifaces(self) -> None:
        from app.core.parsers import parse_iw_interfaces

        out = """phy#0
	Interface wlan0
		ifindex 10
		type managed
	Interface wlan0mon
		ifindex 11
		type monitor
"""
        self.assertEqual(parse_iw_interfaces(out), ["wlan0", "wlan0mon"])

    def test_airodump_csv(self) -> None:
        aps, stas = parse_airodump_csv(SAMPLE_CSV)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0].bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(aps[0].essid, "Test")
        self.assertEqual(aps[0].channel, "6")
        self.assertEqual(len(stas), 1)
        self.assertEqual(stas[0].station_mac, "11:22:33:44:55:66")

    def test_airmon_iface(self) -> None:
        out = "monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon"
        self.assertEqual(parse_airmon_monitor_iface(out), "wlan0mon")

    def test_airmon_already_enabled_ifindex_quirk(self) -> None:
        # RTL8188EUS / some airmon builds: "already enabled" + ifindex after on
        out = (
            "phy0\twlan0\t\trtl8xxxu\tRealtek\n"
            "\t\t(mac80211 monitor mode already enabled for [phy0]wlan0 on [phy0]10)"
        )
        self.assertEqual(parse_airmon_monitor_iface(out), "wlan0")

    def test_iw_monitor_ifaces(self) -> None:
        from app.core.parsers import parse_iw_monitor_interfaces

        out = """phy#0
	Interface wlan0
		ifindex 10
		wdev 0x1
		addr 00:11:22:33:44:55
		type monitor
		channel 1 (2412 MHz), width: 20 MHz
	Interface wlan1
		ifindex 11
		type managed
"""
        self.assertEqual(parse_iw_monitor_interfaces(out), ["wlan0"])

    def test_handshake_line(self) -> None:
        line = " CH  6 ][ Elapsed: 12 s ][ 2024-01-01 00:00 ][ WPA handshake: AA:BB:CC:DD:EE:FF"
        self.assertEqual(
            handshake_from_airodump_line(line),
            "AA:BB:CC:DD:EE:FF",
        )

    def test_aircrack_key(self) -> None:
        out = "KEY FOUND! [ hunter2 ]"
        self.assertEqual(parse_aircrack_key(out), "hunter2")

    def test_handshake_count(self) -> None:
        self.assertTrue(aircrack_reports_handshake("Opening capture.cap\n1 handshake"))
        self.assertFalse(aircrack_reports_handshake("No networks found"))

    def test_airmon_bare_enabled(self) -> None:
        from app.core.parsers import AIRMON_ENABLED_BARE_RE

        out = "(monitor mode enabled)"
        self.assertIsNotNone(AIRMON_ENABLED_BARE_RE.search(out))
        self.assertIsNone(parse_airmon_monitor_iface(out))

    def test_strip_ansi_filters_tui(self) -> None:
        from app.core.parsers import is_useful_airodump_log_line, strip_ansi

        noisy = "\x1b[0m\x1b[2J CH  6 ][ Elapsed: 0 s"
        self.assertFalse(is_useful_airodump_log_line(noisy))
        self.assertIn(
            "WPA handshake",
            strip_ansi("\x1b[37m WPA handshake: AA:BB:CC:DD:EE:FF"),
        )
        self.assertTrue(
            is_useful_airodump_log_line(
                " CH  6 ][ WPA handshake: AA:BB:CC:DD:EE:FF"
            )
        )


if __name__ == "__main__":
    unittest.main()
