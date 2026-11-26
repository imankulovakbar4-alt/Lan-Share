"""Unit tests for bounded LAN Share protocol parsing."""

import io
import json
import unittest

from core.protocol import (
    MAX_HEADER_BYTES,
    MAX_FILE_SIZE,
    read_json_header,
    validate_file_header,
)


class ProtocolHeaderTests(unittest.TestCase):
    def test_reads_json_object(self):
        self.assertEqual(
            read_json_header(io.BytesIO(b'{"type":"hello"}\n')),
            {"type": "hello"},
        )

    def test_rejects_oversized_header(self):
        stream = io.BytesIO(b" " * (MAX_HEADER_BYTES + 1) + b"\n")
        with self.assertRaises(ValueError):
            read_json_header(stream)

    def test_rejects_non_object_json(self):
        with self.assertRaises(ValueError):
            read_json_header(io.BytesIO(b'["not", "an object"]\n'))

    def test_rejects_unterminated_header(self):
        with self.assertRaises(ValueError):
            read_json_header(io.BytesIO(b'{"type":"hello"}'))

    def test_accepts_valid_file_header(self):
        header = {
            "type": "file", "ver": 2, "name": "data.bin",
            "rel": "folder/data.bin", "size": 123,
            "sender": "PC", "sender_id": "a1b2c3",
            "sha256": "a" * 64,
        }
        self.assertEqual(validate_file_header(header), 123)

    def test_rejects_negative_or_excessive_size(self):
        for size in (-1, MAX_FILE_SIZE + 1, True, "not-a-number"):
            header = {"type": "file", "ver": 2, "name": "data.bin", "size": size}
            with self.subTest(size=size), self.assertRaises(ValueError):
                validate_file_header(header)

    def test_rejects_invalid_digest(self):
        header = {"type": "file", "ver": 2, "name": "data.bin",
                  "size": 1, "sha256": "not-a-hash"}
        with self.assertRaises(ValueError):
            validate_file_header(header)


if __name__ == "__main__":
    unittest.main()
