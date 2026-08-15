"""Tests for driver profile matching and USB discovery."""

from __future__ import annotations

import unittest

from app.core.driver_service import DriverService, PROFILES


SAMPLE_LSUSB = """
Bus 001 Device 001: ID 1d6b:0001 Linux Foundation 1.1 root hub
Bus 001 Device 002: ID 80ee:0021 VirtualBox USB Tablet
Bus 001 Device 003: ID 2357:0109 TP-Link TL-WN823N v2/v3 [Realtek RTL8192EU]
"""


class DriverServiceTests(unittest.TestCase):
    def test_rtl8188eus_usb_match(self) -> None:
        svc = DriverService()
        prof = svc._match_profile("Bus 001 Device 003: ID 0bda:8179 Realtek RTL8188EUS")
        self.assertIsNotNone(prof)
        assert prof is not None
        self.assertEqual(prof.id, "rtl8188eus")
        self.assertEqual(prof.apt_package, "realtek-rtl8188eus-dkms")

    def test_rtl8192eu_tplink_wn823n(self) -> None:
        svc = DriverService()
        prof = svc._match_profile(
            "Bus 001 Device 003: ID 2357:0109 TP-Link TL-WN823N v2/v3 [Realtek RTL8192EU]"
        )
        self.assertIsNotNone(prof)
        assert prof is not None
        self.assertEqual(prof.id, "rtl8192eu")
        self.assertEqual(prof.good_module, "8192eu")
        self.assertEqual(prof.install_method, "git_dkms")
        self.assertIn("Mange", prof.git_url)

    def test_parse_wireless_usb_generic(self) -> None:
        svc = DriverService()
        devs = svc.parse_wireless_usb_devices(SAMPLE_LSUSB)
        self.assertEqual(len(devs), 1)
        self.assertEqual(devs[0]["usb_ids"], "2357:0109")
        self.assertIn("TL-WN823N", devs[0]["usb"])

    def test_rtl8xxxu_chipset_keyword(self) -> None:
        svc = DriverService()
        prof = svc._match_profile(
            "phy0 wlan0 rtl8xxxu Realtek Semiconductor Corp. RTL8188EUS"
        )
        self.assertIsNotNone(prof)
        assert prof is not None
        self.assertEqual(prof.good_module, "8188eu")

    def test_parse_airmon_skips_header(self) -> None:
        svc = DriverService()
        text = """
Found 2 processes that could cause trouble.

PHY	Interface	Driver		Chipset

phy0	wlan0		rtl8xxxu	Realtek Semiconductor Corp. RTL8188EUS
"""
        rows = svc._parse_airmon_table(text)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["iface"], "wlan0")
        self.assertEqual(rows[0]["driver"], "rtl8xxxu")
        self.assertNotIn("Interface", [r["iface"] for r in rows])

    def test_parse_airmon_skips_phy_only_header(self) -> None:
        svc = DriverService()
        rows = svc._parse_airmon_table("PHY  Interface  Driver  Chipset")
        self.assertEqual(rows, [])

    def test_profiles_have_install_path(self) -> None:
        for p in PROFILES:
            self.assertTrue(p.good_module)
            if p.install_method == "apt":
                self.assertTrue(p.apt_package)
            else:
                self.assertTrue(p.git_url)


if __name__ == "__main__":
    unittest.main()
