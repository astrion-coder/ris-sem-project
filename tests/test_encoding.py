import unittest

from ris_sem_project.primitives import encoding


class EncodingTest(unittest.TestCase):
    def test_round_trip_with_empty_fields(self):
        for fields in [(), (b"",), (b"", b""), (b"a", b"", b"bcd"), (bytes(300), b"x")]:
            self.assertEqual(encoding.unpack(encoding.pack(*fields), len(fields)), fields)

    def test_known_layout(self):
        self.assertEqual(encoding.pack(b"ab", b""), b"\x00\x00\x00\x02ab\x00\x00\x00\x00")

    def test_injective_where_concatenation_collides(self):
        self.assertNotEqual(encoding.pack(b"ab", b"c"), encoding.pack(b"a", b"bc"))
        self.assertNotEqual(encoding.pack(b"", b"a"), encoding.pack(b"a", b""))

    def test_malformed_shapes_raise(self):
        good = encoding.pack(b"ab", b"c")
        cases = [
            (good[:-1], 2),
            (good + b"\x00", 2),
            (good, 1),
            (good, 3),
            (b"", 1),
            (b"\x00\x00", 1),
            (b"\xff\xff\xff\xff" + b"abc", 1),
            (b"\x00\x00\x00\x05abc", 1),
        ]
        for data, count in cases:
            with self.assertRaises(ValueError, msg=(data, count)):
                encoding.unpack(data, count)

    def test_int_helpers(self):
        self.assertEqual(encoding.int_bytes(258), b"\x00\x00\x01\x02")
        self.assertEqual(encoding.int_bytes(258, 2), b"\x01\x02")
        self.assertEqual(encoding.bytes_int(b"\x01\x02"), 258)
        self.assertEqual(encoding.bytes_int(b""), 0)
        q = 8380417
        self.assertEqual(encoding.bytes_int(encoding.int_bytes(q - 1)), q - 1)
        with self.assertRaises(OverflowError):
            encoding.int_bytes(2**32)


if __name__ == "__main__":
    unittest.main()
