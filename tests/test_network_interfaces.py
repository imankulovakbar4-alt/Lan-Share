"""Tests for local IPv4 selection helpers."""

import unittest
from unittest.mock import patch

from core.network.interfaces import _usable_ipv4, get_local_ipv4


class NetworkInterfaceTests(unittest.TestCase):
    def test_rejects_loopback_and_link_local_addresses(self):
        self.assertFalse(_usable_ipv4("127.0.0.1"))
        self.assertFalse(_usable_ipv4("169.254.10.2"))
        self.assertTrue(_usable_ipv4("192.168.1.20"))

    @patch("core.network.interfaces._route_probe", return_value="10.0.0.5")
    def test_prefers_route_selected_source_address(self, _probe):
        self.assertEqual(get_local_ipv4(), "10.0.0.5")

    @patch("core.network.interfaces._route_probe", return_value=None)
    @patch("core.network.interfaces._psutil_addresses", return_value=["192.168.1.7"])
    def test_uses_interface_fallback_without_default_route(self, _addresses, _probe):
        self.assertEqual(get_local_ipv4(), "192.168.1.7")

    @patch("core.network.interfaces._route_probe", return_value=None)
    @patch("core.network.interfaces._psutil_addresses", return_value=[])
    @patch("core.network.interfaces._hostname_addresses", return_value=[])
    def test_returns_loopback_when_no_network_exists(self, _hostname, _psutil, _probe):
        self.assertEqual(get_local_ipv4(), "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
