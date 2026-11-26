"""Tests for LAN Share UDP discovery packet validation."""

import json
import unittest

from core.network.discovery import (
    MAX_DISCOVERY_BYTES,
    decode_discovery_packet,
    normalize_announcement,
)


class DiscoveryTests(unittest.TestCase):
    def test_decodes_json_object(self):
        self.assertEqual(decode_discovery_packet(b'{"type":"query","code":"ABC123"}'),
                         {"type": "query", "code": "ABC123"})

    def test_rejects_malformed_non_object_and_oversized_packets(self):
        self.assertIsNone(decode_discovery_packet(b"{broken"))
        self.assertIsNone(decode_discovery_packet(b"[]"))
        self.assertIsNone(decode_discovery_packet(b"x" * (MAX_DISCOVERY_BYTES + 1)))

    def test_normalizes_announcement_using_observed_source_ip(self):
        packet = {
            "id": "peer-1", "host": "Laptop", "ip": "203.0.113.9",
            "port": 51314, "room": "ABC234", "access": "public",
            "hidden": False,
        }
        result = normalize_announcement(packet, "192.168.1.25")
        self.assertEqual(result["ip"], "192.168.1.25")
        self.assertEqual(result["port"], 51314)
        self.assertEqual(result["id"], "peer-1")

    def test_rejects_invalid_peer_id_and_port(self):
        base = {"id": "peer", "host": "PC", "port": 51314}
        self.assertIsNone(normalize_announcement({**base, "id": ""}, "192.168.1.2"))
        self.assertIsNone(normalize_announcement({**base, "port": True}, "192.168.1.2"))
        self.assertIsNone(normalize_announcement({**base, "port": 65536}, "192.168.1.2"))
        self.assertIsNone(normalize_announcement({**base, "port": "51314"}, "192.168.1.2"))

    def test_query_is_not_an_announcement(self):
        self.assertIsNone(normalize_announcement({"type": "query"}, "192.168.1.2"))


if __name__ == "__main__":
    unittest.main()
