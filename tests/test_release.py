import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("publish_release", Path(__file__).parents[1] / "bin/publish-release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def run_release(self, existing=None, corrupt=False, listing_fails=False):
        self.calls = []
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "host.ps1"
            source.write_bytes(b"\xef\xbb\xbfhost\r\n")

            def fake_gh(*args):
                self.calls.append(args)
                if args[0] == "api":
                    if listing_fails:
                        raise subprocess.CalledProcessError(1, "gh")
                    return json.dumps([[existing] if existing else []])
                if args[1] in ("create", "upload"):
                    self.assertEqual(Path(args[3]).name, "AppUpdater.ps1")
                    self.assertEqual(Path(args[3]).read_bytes(), source.read_bytes())
                if args[1] == "download":
                    (Path(args[-1]) / "AppUpdater.ps1").write_bytes(b"wrong" if corrupt else source.read_bytes())
                return ""

            with patch.object(release, "gh", fake_gh):
                release.publish("v1", "abc", "owner/repo", source)

    def test_new_release_is_verified_before_publishing(self):
        self.run_release()
        self.assertEqual([c[1] for c in self.calls[1:]], ["create", "download", "edit"])

    def test_matching_draft_is_resumed(self):
        self.run_release({"tag_name": "v1", "draft": True, "target_commitish": "abc"})
        self.assertEqual([c[1] for c in self.calls[1:]], ["upload", "download", "edit"])

    def test_mismatched_draft_is_untouched(self):
        with self.assertRaises(RuntimeError):
            self.run_release({"tag_name": "v1", "draft": True, "target_commitish": "old"})
        self.assertEqual(len(self.calls), 1)

    def test_published_release_is_untouched(self):
        self.run_release({"tag_name": "v1", "draft": False})
        self.assertEqual(len(self.calls), 1)

    def test_corrupt_asset_stays_draft(self):
        with self.assertRaises(RuntimeError):
            self.run_release(corrupt=True)
        self.assertFalse(any(c[:2] == ("release", "edit") for c in self.calls))

    def test_failed_lookup_does_not_create_release(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_release(listing_fails=True)
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
