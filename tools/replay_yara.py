#!/usr/bin/env python3
"""Read-only YARA replay for explicitly selected case files and archives.

The tool scans raw files and reads ZIP, VSIX, TAR and gzip members in memory.
It never writes archive members or executes their contents. RAR members are
reported as unsupported; the raw RAR file is still scanned.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import tarfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Iterator

import yara


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "yara"
MAX_OBJECT_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 20_000
MAX_DEPTH = 4


def selected_files(root: Path, targets: list[str]) -> Iterator[Path]:
    root = root.resolve(strict=True)
    found: set[Path] = set()
    for raw in targets:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = root / candidate
        if candidate.is_symlink():
            continue
        candidate = candidate.resolve(strict=True)
        if not candidate.is_relative_to(root):
            raise ValueError(f"Target is outside --root: {raw}")
        if candidate.is_file():
            found.add(candidate)
            continue
        if not candidate.is_dir():
            continue
        for current, dirs, names in os.walk(candidate, followlinks=False):
            dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
            for name in names:
                item = Path(current) / name
                if item.is_file() and not item.is_symlink():
                    found.add(item.resolve())
    yield from sorted(found)


def archive_kind(data: bytes) -> str | None:
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"Rar!\x1a\x07"):
        return "rar"
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*"):
            return "tar"
    except (tarfile.TarError, OSError, EOFError):
        return None


def replay(root: Path, targets: list[str], details: bool = False) -> dict:
    root = root.resolve(strict=True)
    rule_paths = sorted(RULES.glob("*.yar"))
    if not rule_paths:
        raise RuntimeError(f"No YARA rules found in {RULES}")
    rules = yara.compile(filepaths={path.stem: str(path) for path in rule_paths})

    stats = Counter()
    matched_objects: dict[str, set[str]] = {}
    matched_files: dict[str, set[str]] = {}
    matches = []
    skipped = []
    budget = [0]

    def scan_object(label: str, parent: str, data: bytes) -> None:
        stats["objects"] += 1
        stats["bytes"] += len(data)
        budget[0] += len(data)
        try:
            hits = rules.match(data=data, timeout=10)
        except yara.TimeoutError:
            stats["timeouts"] += 1
            skipped.append({"object": label, "reason": "YARA timeout"})
            return
        if not hits:
            return
        stats["matched_objects"] += 1
        rule_names = sorted({hit.rule for hit in hits})
        for rule_name in rule_names:
            matched_objects.setdefault(rule_name, set()).add(label)
            matched_files.setdefault(rule_name, set()).add(parent)
        if details:
            matches.append({"object": label, "rules": rule_names})

    def visit(label: str, parent: str, data: bytes, depth: int = 0) -> None:
        if len(data) > MAX_OBJECT_BYTES:
            stats["oversize"] += 1
            skipped.append({"object": label, "reason": "object size limit"})
            return
        if budget[0] + len(data) > MAX_TOTAL_BYTES:
            stats["budget_exhausted"] += 1
            skipped.append({"object": label, "reason": "scan byte budget"})
            return

        scan_object(label, parent, data)
        kind = archive_kind(data)
        if kind is None:
            return
        if kind == "rar":
            stats["unsupported_rar"] += 1
            skipped.append({"object": label, "reason": "RAR members are not decoded"})
            return
        if depth >= MAX_DEPTH:
            stats["depth_limited"] += 1
            skipped.append({"object": label, "reason": "archive nesting limit"})
            return

        if kind == "zip":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    for info in archive.infolist():
                        if info.is_dir():
                            continue
                        stats["members_seen"] += 1
                        if stats["members_seen"] > MAX_MEMBERS:
                            skipped.append({"object": label, "reason": "archive member count limit"})
                            return
                        if info.file_size > MAX_OBJECT_BYTES:
                            stats["oversize_members"] += 1
                            skipped.append({"object": f"{label}::{info.filename}", "reason": "member size limit"})
                            continue
                        member_label = f"{label}::{info.filename}"
                        try:
                            member = archive.read(info)
                        except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                            stats["member_errors"] += 1
                            skipped.append({"object": member_label, "reason": type(error).__name__})
                            continue
                        visit(member_label, parent, member, depth + 1)
            except (OSError, zipfile.BadZipFile) as error:
                stats["archive_errors"] += 1
                skipped.append({"object": label, "reason": f"ZIP parse: {type(error).__name__}"})
        elif kind == "gzip":
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
                    expanded = stream.read(MAX_OBJECT_BYTES + 1)
                if len(expanded) > MAX_OBJECT_BYTES:
                    stats["oversize_members"] += 1
                    skipped.append({"object": f"{label}::gzip-content", "reason": "member size limit"})
                    return
                visit(f"{label}::gzip-content", parent, expanded, depth + 1)
            except (OSError, EOFError) as error:
                stats["archive_errors"] += 1
                skipped.append({"object": label, "reason": f"gzip parse: {type(error).__name__}"})
        elif kind == "tar":
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                    for info in archive:
                        if not info.isfile():
                            continue
                        stats["members_seen"] += 1
                        if stats["members_seen"] > MAX_MEMBERS:
                            skipped.append({"object": label, "reason": "archive member count limit"})
                            return
                        if info.size > MAX_OBJECT_BYTES:
                            stats["oversize_members"] += 1
                            skipped.append({"object": f"{label}::{info.name}", "reason": "member size limit"})
                            continue
                        stream = archive.extractfile(info)
                        if stream is None:
                            continue
                        member = stream.read(MAX_OBJECT_BYTES + 1)
                        if len(member) > MAX_OBJECT_BYTES:
                            stats["oversize_members"] += 1
                            skipped.append({"object": f"{label}::{info.name}", "reason": "member size limit"})
                            continue
                        visit(f"{label}::{info.name}", parent, member, depth + 1)
            except (tarfile.TarError, OSError, EOFError) as error:
                stats["archive_errors"] += 1
                skipped.append({"object": label, "reason": f"TAR parse: {type(error).__name__}"})

    files = list(selected_files(root, targets))
    for path in files:
        relative = path.relative_to(root).as_posix()
        stats["files"] += 1
        try:
            size = path.stat().st_size
            if size > MAX_OBJECT_BYTES:
                stats["oversize"] += 1
                skipped.append({"object": relative, "reason": "file size limit"})
                continue
            data = path.read_bytes()
        except OSError as error:
            stats["read_errors"] += 1
            skipped.append({"object": relative, "reason": type(error).__name__})
            continue
        visit(relative, relative, data)

    return {
        "rules": len(rule_paths),
        "files": stats["files"],
        "objects": stats["objects"],
        "bytes_scanned": stats["bytes"],
        "objects_with_matches": stats["matched_objects"],
        "matches_by_rule": {
            name: {"objects": len(objects), "input_files": len(matched_files[name])}
            for name, objects in sorted(matched_objects.items())
        },
        "skipped_counts": dict(sorted(Counter(x["reason"] for x in skipped).items())),
        "skipped": skipped,
        **({"matches": matches} if details else {}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="Root used to resolve and redact target paths")
    parser.add_argument("--details", action="store_true", help="Include matched object labels and rule names in JSON output")
    parser.add_argument("targets", nargs="+", help="Files or directories under --root; directories are scanned recursively")
    args = parser.parse_args()
    try:
        result = replay(args.root, args.targets, args.details)
    except (OSError, ValueError, yara.Error) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
