#!/usr/bin/env python3
"""Decode/re-embed the engine without executing PowerShell startup code."""
import argparse
import base64
import difflib
from pathlib import Path
import re
import subprocess


def decode(source):
    match = re.search(r"(?m)^\$__CoreB64Chunks = @\(\r?\n(.*?)^\)", source, re.S)
    if not match:
        raise ValueError("Embedded engine block not found")
    chunks = re.findall(r"'([A-Za-z0-9+/=]+)'", match[1])
    return match, base64.b64decode("".join(chunks), validate=True).decode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["extract", "embed", "check", "diff"])
    parser.add_argument("engine", type=Path, nargs="?")
    parser.add_argument("--host", type=Path, default=Path("host.ps1"))
    args = parser.parse_args()
    if args.operation != "diff" and args.engine is None:
        parser.error("engine path is required for extract, embed, and check")
    source = args.host.read_bytes().decode("utf-8")
    match, core = decode(source)
    if args.operation == "diff":
        previous = subprocess.check_output(["git", "show", f"HEAD:{args.host.as_posix()}"]).decode("utf-8")
        _, previous_core = decode(previous)
        print("".join(difflib.unified_diff(previous_core.splitlines(True), core.splitlines(True),
                                         fromfile="HEAD:embedded-engine", tofile="embedded-engine")), end="")
    elif args.operation == "extract":
        # Never overwrite a separately edited copy.
        with args.engine.open("x", encoding="utf-8", newline="") as output:
            output.write(core)
    elif args.operation == "check":
        if args.engine.read_bytes().decode("utf-8") != core:
            raise SystemExit("Engine differs from embedded source")
    else:
        encoded = base64.b64encode(args.engine.read_bytes()).decode("ascii")
        chunks = "".join("  '" + encoded[i:i + 32768] + "'\n" for i in range(0, len(encoded), 32768))
        updated = source[:match.start(1)] + chunks + source[match.end(1):]
        args.host.write_bytes(updated.encode("utf-8"))


if __name__ == "__main__":
    main()
