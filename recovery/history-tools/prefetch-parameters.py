#!/usr/bin/env python3
# Copyright (c) 2019-2026 Provable Inc.
# Licensed under the Apache License, Version 2.0.
"""Stage a bounded set of checksum-pinned classical proving parameters.

This does not install files into the user's Aleo cache. It preserves TLS
certificate verification and validates the source tree's full SHA-256 and size.
"""

import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import re
import subprocess
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGETS = {}
for degree in (18, 19):
    for stem in ("powers-of-beta", "shifted-powers-of-beta"):
        name = f"{stem}-{degree}"
        TARGETS[f"mainnet/{name}"] = (f"mainnet/resources/{name}.metadata", name, "usrs")
for network in ("mainnet", "testnet"):
    for version in ("credits_v0", "credits"):
        TARGETS[f"{network}/{version}/inclusion"] = (
            f"{network}/resources/{version}/inclusion.metadata", "inclusion", "prover"
        )
for version in ("credits_v0", "credits"):
    for function in ("transfer_private", "fee_public", "upgrade"):
        TARGETS[f"testnet/{version}/{function}"] = (
            f"testnet/resources/{version}/{function}.metadata", function, "prover"
        )
    for function in ("transfer_public", "fee_public"):
        TARGETS[f"mainnet/{version}/{function}"] = (
            f"mainnet/resources/{version}/{function}.metadata", function, "prover"
        )


def checksum(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def descriptor(target):
    relative, name, kind = TARGETS[target]
    metadata_path = ROOT / "parameters/src" / relative
    raw = metadata_path.read_bytes()
    metadata = json.loads(raw)
    prefix = "" if kind == "usrs" else f"{kind}_"
    digest, size = metadata[f"{prefix}checksum"], metadata[f"{prefix}size"]
    if not re.fullmatch("[0-9a-f]{64}", digest) or not isinstance(size, int) or not 0 < size <= 300 * 1024 * 1024:
        raise ValueError(f"Invalid bounded metadata: {target}")
    return {
        "file": f"{name}.{kind}.{digest[:7]}", "sha256": digest, "bytes": size,
        "targets": [target], "metadata": [str(metadata_path.relative_to(ROOT))],
        "metadata_sha256": [hashlib.sha256(raw).hexdigest()],
    }


def download(entry, output):
    destination = output / entry["file"]
    if destination.exists():
        if destination.stat().st_size != entry["bytes"] or checksum(destination) != entry["sha256"]:
            raise ValueError(f"Existing staged parameter is invalid: {destination}")
        return entry | {"retrieval": "already staged; size and full SHA-256 rechecked"}
    temporary = destination.with_name(destination.name + ".part")
    failures = []
    networks = sorted({target.split("/", 1)[0] for target in entry["targets"]})
    for network in networks:
        for base in (f"https://parameters.provable.com/{network}",
                     f"https://s3.us-west-1.amazonaws.com/{network}.parameters"):
            url = f"{base}/{entry['file']}"
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "Aleo reproducible parameter prefetch"})
                with urllib.request.urlopen(request, timeout=30) as response, temporary.open("wb") as sink:
                    size = 0
                    while chunk := response.read(1024 * 1024):
                        size += len(chunk)
                        if size > entry["bytes"]:
                            raise ValueError(f"Oversized parameter response: {url}")
                        sink.write(chunk)
                if temporary.stat().st_size != entry["bytes"] or checksum(temporary) != entry["sha256"]:
                    raise ValueError(f"Parameter size or SHA-256 mismatch: {url}")
                temporary.replace(destination)
                return entry | {"url": url, "tls_verification": "Python default verified SSL context"}
            except Exception as error:
                failures.append(f"{url}: {error}")
                temporary.unlink(missing_ok=True)
    raise RuntimeError("All verified parameter sources failed: " + "; ".join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--target", action="append", choices=sorted(TARGETS))
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)
    selected = arguments.target or sorted(TARGETS)
    unique = {}
    for target in selected:
        entry = descriptor(target)
        previous = unique.get(entry["file"])
        if previous is not None:
            if (previous["sha256"], previous["bytes"]) != (entry["sha256"], entry["bytes"]):
                raise ValueError("Conflicting metadata for the same parameter filename")
            for key in ("targets", "metadata", "metadata_sha256"):
                previous[key].extend(entry[key])
        else:
            unique[entry["file"]] = entry
    if sum(entry["bytes"] for entry in unique.values()) > 1024 * 1024 * 1024:
        raise ValueError("Selected classical parameters exceed the one GiB staging limit")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda entry: download(entry, arguments.output), unique.values()))
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = {
        "source_revision": revision,
        "scope": "Historical classical credits proving only; no post-quantum ownership proof claim",
        "installation": "Staging only; no Aleo home or system configuration modified",
        "files": sorted(results, key=lambda entry: entry["file"]),
    }
    (arguments.output / "prefetch-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for entry in manifest["files"]:
        print(f"VERIFIED {entry['file']} bytes={entry['bytes']} sha256={entry['sha256']}")


if __name__ == "__main__":
    main()
