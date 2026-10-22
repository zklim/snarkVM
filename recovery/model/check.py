#!/usr/bin/env python3
"""Check the bounded target model, five mutants and three progress witnesses.

This is specification testing, not refinement checking of the Rust implementation.
Requires Java 21. The downloaded TLC release is checked before execution.
"""

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
import time
import urllib.request


URL = "https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"
SHA256 = "5bd7b64db99ae4c6c35f290de5e809c0ee41af43f8699cf696099ffb6452b1e2"
MUTANTS = {
    "CandidateHeightGate": "NoRetiredLegacy",
    "CheckSpent": "Conservation|NoDoubleSpend",
    "AtomicStorage": "Conservation",
    "CheckEffectBinding": "ProofContract",
    "ScopeReplayByEffects": "ReplayIsolation",
}
COVERS = ("NoV2Created", "NoV3Created", "NoV3Consumed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.jar = args.jar.resolve()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.jar.exists():
        args.jar.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(URL, timeout=60) as response:
            args.jar.write_bytes(response.read())
    actual = hashlib.sha256(args.jar.read_bytes()).hexdigest()
    if actual != SHA256:
        raise SystemExit(f"TLC checksum mismatch: {actual}")

    source = pathlib.Path(__file__).resolve().parent
    config = (source / "Recovery.cfg").read_text()
    cases = [("baseline", config, None)] + [
        (name, config.replace(f"{name} = TRUE", f"{name} = FALSE"), invariant)
        for name, invariant in MUTANTS.items()
    ] + [
        (f"cover-{invariant}", config + f"\nINVARIANT {invariant}\n", invariant)
        for invariant in COVERS
    ]
    results = []
    for name, content, expected in cases:
        with tempfile.TemporaryDirectory(prefix=f"recovery-{name}-") as temporary:
            temporary = pathlib.Path(temporary)
            cfg = temporary / "Recovery.cfg"
            cfg.write_text(content)
            command = [
                "java", "-Xmx2g", "-XX:+UseParallelGC", "-cp", str(args.jar),
                "tlc2.TLC", "-workers", "4", "-fp", "0", "-seed", "1",
                "-metadir", str(temporary / "states"), "-config", str(cfg),
                "Recovery.tla",
            ]
            started = time.monotonic()
            completed = subprocess.run(command, cwd=source, text=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       timeout=600, check=False)
            elapsed = time.monotonic() - started
            log = completed.stdout
            (args.output / f"{name}.log").write_text(log)
            passed = (
                completed.returncode == 0
                and "Model checking completed. No error has been found." in log
                if expected is None else
                completed.returncode == 12
                and re.search(rf"Invariant ({expected}) is violated", log) is not None
                and "The behavior up to this point is:" in log
            )
            states = re.search(r"([\d,]+) states generated, ([\d,]+) distinct states", log)
            result = {
                "case": name, "passed": bool(passed), "exit_code": completed.returncode,
                "expected_violation": expected, "seconds": round(elapsed, 3),
                "states": states.groups() if states else None,
                "log_sha256": hashlib.sha256(log.encode()).hexdigest(),
            }
            results.append(result)
            print(json.dumps(result), flush=True)
            (args.output / "results.json").write_text(json.dumps({
                "tlc_url": URL, "tlc_sha256": SHA256,
                "source_sha256": hashlib.sha256((source / "Recovery.tla").read_bytes()).hexdigest(),
                "scope": "bounded target specification; not Rust refinement or a cryptographic proof",
                "results": results,
            }, indent=2) + "\n")
            if not passed:
                raise SystemExit(f"unexpected TLC result for {name}; inspect retained log")


if __name__ == "__main__":
    main()
