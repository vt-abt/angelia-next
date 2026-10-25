import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "memory_compare", Path(__file__).resolve().parents[1] / "tools/memory_validation/compare.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MemoryComparisonTest(unittest.TestCase):
    def setUp(self):
        self.angelia = {
            "dump_format": "PAGEDU64", "walk_complete": True,
            "entries": [
                {"pid": 4, "image_raw": "System", "eprocess_va": "0xffff800000001000", "seen_in_raw_walk": True},
                {"pid": 100, "image_raw": "notepad.exe", "eprocess_va": "0xffff800000002000", "seen_in_raw_walk": True},
            ],
        }
        self.volatility = [
            {"PID": 4, "ImageFileName": "System", "Offset(V)": "0xffff800000001000", "__children": []},
            {"PID": 100, "ImageFileName": "notepad.exe", "Offset(V)": "0xffff800000002000", "__children": []},
        ]

    def test_same_dump_processes_match(self):
        self.assertTrue(module.compare(self.angelia, self.volatility)["matched"])

    def test_missing_and_name_mismatch_are_reported(self):
        self.volatility[1]["ImageFileName"] = "other.exe"
        self.volatility.append({"PID": 200, "ImageFileName": "calc.exe", "Offset(V)": "0x3000"})
        result = module.compare(self.angelia, self.volatility)
        self.assertFalse(result["matched"])
        self.assertEqual(result["missing_in_angelia"], [200])
        self.assertEqual(result["image_differences"][0]["pid"], 100)

    def test_partial_walk_is_not_validated(self):
        self.angelia["walk_complete"] = False
        with self.assertRaisesRegex(ValueError, "partial"):
            module.compare(self.angelia, self.volatility)


if __name__ == "__main__":
    unittest.main()
