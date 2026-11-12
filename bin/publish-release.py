#!/usr/bin/env python3
"""Publish the validated host source under the stable download filename."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True)


def publish(tag, commit, repo, source):
    # Listing must succeed: an authentication/network failure is not "missing".
    pages = json.loads(gh("api", f"repos/{repo}/releases?per_page=100", "--paginate", "--slurp"))
    existing = next((r for page in pages for r in page if r["tag_name"] == tag), None)
    if existing and not existing["draft"]:
        print(f"{tag} already published")
        return
    if existing and existing["target_commitish"] != commit:
        raise RuntimeError(f"Draft {tag} belongs to another commit; review it before retrying.")
    with tempfile.TemporaryDirectory(prefix="appupdater-release-") as directory:
        asset = Path(directory) / "AppUpdater.ps1"
        shutil.copyfile(source, asset)
        if asset.read_bytes() != source.read_bytes():
            raise RuntimeError("Release copy differs from host.ps1")
        if existing:
            gh("release", "upload", tag, str(asset), "--clobber")
        else:
            gh("release", "create", tag, str(asset), "--draft", "--target", commit,
               "--title", f"AppUpdater {tag}", "--generate-notes",
               "--notes", f"Download AppUpdater.ps1 and run it in Windows PowerShell 5.1 as admin.\n\n"
                          f"Always-latest link: https://github.com/{repo}/releases/latest/download/AppUpdater.ps1")
        downloaded = Path(directory) / "downloaded"
        downloaded.mkdir()
        gh("release", "download", tag, "--pattern", "AppUpdater.ps1", "--dir", str(downloaded))
        if (downloaded / "AppUpdater.ps1").read_bytes() != source.read_bytes():
            raise RuntimeError("Downloaded release asset differs from host.ps1; release remains a draft.")
        gh("release", "edit", tag, "--draft=false")
        print(f"Published {tag}: AppUpdater.ps1 is byte-for-byte identical to host.ps1")


if __name__ == "__main__":
    version = subprocess.check_output(["python3", ".github/check-version.py"], text=True).strip()
    publish(f"v{version}", os.environ["GITHUB_SHA"], os.environ["GITHUB_REPOSITORY"], Path("host.ps1"))
