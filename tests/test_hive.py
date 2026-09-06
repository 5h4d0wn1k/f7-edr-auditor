import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from edr_auditor.hive import (
    HiveBuilder, HiveRegistry, HiveError, REG_DWORD, REG_MULTI_SZ, REG_SZ,
    REG_EXPAND_SZ, REG_BINARY,
)


class _TmpHiveBuilder:
    def __init__(self, test_case):
        self.directory = test_case._tempdir = os.path.join(
            "/tmp", "edr_test_hive_%d" % os.getpid())
        os.makedirs(self.directory, exist_ok=True)
        self.path = os.path.join(self.directory, "fixture.DAT")
        for old in os.listdir("/tmp"):
            continue


class TestHiveBuilderRoundTrip(unittest.TestCase):
    def setUp(self):
        self.workdir = "/tmp/edr_test_hive_%d" % os.getpid()
        os.makedirs(self.workdir, exist_ok=True)
        self.hive_path = os.path.join(self.workdir, "ROOT.DAT")

    def build_and_open(self):
        b = HiveBuilder()
        b.add_key("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        b.add_value("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "One", REG_SZ, "C:\\Users\\Public\\one.exe")
        b.add_value("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Count", REG_DWORD, 7)
        b.add_value("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "List", REG_MULTI_SZ, ["a", "b"])
        b.add_value("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Expand", REG_EXPAND_SZ, "%SystemRoot%\\system32\\x.exe")
        b.add_value("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Blob", REG_BINARY, b"\x00\x01\xfe\xff")
        b.add_key("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
        b.add_value("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "Once", REG_SZ, "cmd /c del x")
        b.write(self.hive_path)
        return HiveRegistry(self.hive_path)

    def test_header_and_root(self):
        hive = self.build_and_open()
        self.assertEqual(hive.major, 1)
        self.assertIsNotNone(hive.root())
        self.assertEqual(hive.root().name, "ROOT")

    def test_open_key_navigation(self):
        hive = self.build_and_open()
        node = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        self.assertIsNotNone(node)
        self.assertEqual(node.name, "Run")
        names = [c.name for c in node.subkeys()]
        self.assertEqual(names, [])

    def test_subkey_enumeration(self):
        hive = self.build_and_open()
        root = hive.root()
        first = root.subkeys()[0]
        self.assertEqual(first.name, "Software")
        self.assertEqual(first.subkey("Microsoft").name, "Microsoft")

    def test_value_decoding(self):
        hive = self.build_and_open()
        node = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        vals = {v.name: v for v in node.values()}
        self.assertEqual(vals["One"].data, "C:\\Users\\Public\\one.exe")
        self.assertEqual(vals["One"].type, REG_SZ)
        self.assertEqual(vals["Count"].data, 7)
        self.assertEqual(vals["List"].data, ["a", "b"])
        self.assertEqual(vals["Expand"].data, "%SystemRoot%\\system32\\x.exe")
        self.assertEqual(vals["Blob"].data, "0001feff")

    def test_get_value(self):
        hive = self.build_and_open()
        node = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        self.assertEqual(node.get_value("Count").data, 7)
        self.assertIsNone(node.get_value("DoesNotExist"))

    def test_run_once_key(self):
        hive = self.build_and_open()
        node = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
        self.assertEqual(node.get_value("Once").data, "cmd /c del x")

    def test_open_missing_key_returns_none(self):
        hive = self.build_and_open()
        self.assertIsNone(hive.open_key("Software\\Nope\\Nothing"))


class TestHiveParsingRobustness(unittest.TestCase):
    def test_rejects_non_hive_file(self):
        path = "/tmp/edr_notaregf.txt"
        with open(path, "w") as fh:
            fh.write("not a hive")
        with self.assertRaises(HiveError):
            HiveRegistry(path)

    def test_reads_binary_data(self):
        workdir = "/tmp/edr_test_bin_%d" % os.getpid()
        os.makedirs(workdir, exist_ok=True)
        path = os.path.join(workdir, "BIN.DAT")
        b = HiveBuilder()
        b.add_key("K")
        b.add_value("K", "D", REG_BINARY, b"\xde\xad\xbe\xef\x01\x02")
        b.write(path)
        hive = HiveRegistry(path)
        node = hive.open_key("K")
        self.assertEqual(node.get_value("D").raw, b"\xde\xad\xbe\xef\x01\x02")

    def test_unicode_value(self):
        workdir = "/tmp/edr_test_uni_%d" % os.getpid()
        os.makedirs(workdir, exist_ok=True)
        path = os.path.join(workdir, "U.DAT")
        b = HiveBuilder()
        b.add_key("K")
        b.add_value("K", "名前", REG_SZ, "値")
        b.write(path)
        hive = HiveRegistry(path)
        node = hive.open_key("K")
        self.assertEqual(node.get_value("名前").data, "値")


if __name__ == "__main__":
    unittest.main()