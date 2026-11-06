#!/usr/bin/env python3
"""Independent finite transition specification for disclosed credits recovery.

This models state transitions and assumes authenticated membership and valid
cryptographic predicates. It is not extracted from Rust and does not prove
cryptographic soundness, consensus security, or implementation refinement.
"""

import argparse
from collections import deque
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import time


H1, H2 = 2, 4
MAX_SLOTS = 6
# Bounded values are units, not a rescaling of the production cap. The exact
# microcredit limits are checked separately in boundary_vectors().
KEYS = ("F0", "M0")
CATEGORY = {"L": 0, "F0": 1, "F1": 1, "M0": 3, "M1": 3}
KINDS = ("legacy", "private_fee", "prepare", "migrate", "spend", "rotate")


@dataclass(frozen=True)
class Record:
    version: int
    amount: int
    key: str


@dataclass(frozen=True)
class State:
    height: int = 0
    records: tuple = (Record(0, 3, "L"), Record(1, 3, "L"))
    consumed: frozenset = frozenset()
    fees: int = 0


@dataclass(frozen=True)
class Tx:
    kind: str
    source: int
    key: str = "F0"
    owner_authorized: bool = True
    input_authorized: bool = True
    recipient_possession: bool = True
    opening_member: bool = True
    exact_effects: bool = True
    same_chain: bool = True
    nonce: int = 0


def phase(height):
    return 0 if height < H1 else 1 if height < H2 else 2


def allowed(version, kind, height):
    p = phase(height)
    return (
        (kind in ("legacy", "private_fee") and p == 0 and version in (0, 1))
        or (kind == "prepare" and p == 1 and version in (0, 1))
        or (kind == "migrate" and p == 2 and version == 2)
        or (kind == "spend" and p == 2 and version == 3)
        or (kind == "rotate" and ((p == 1 and version == 2) or (p == 2 and version == 3)))
    )


def apply(state, tx, *, check_spent=True, check_effects=True, check_pop=True,
          check_category=True, candidate_height=True, atomic=True):
    """Return a complete new state or None; no mutation on rejection."""
    if tx.source >= len(state.records):
        return None
    source = state.records[tx.source]
    at_height = state.height + (1 if candidate_height else 0)
    if not allowed(source.version, tx.kind, at_height):
        return None
    if check_spent and tx.source in state.consumed:
        return None
    if not tx.same_chain or not tx.opening_member:
        return None
    if check_effects and not tx.exact_effects:
        return None
    if source.version < 2 and not tx.owner_authorized:
        return None
    if source.version >= 2 and not tx.input_authorized:
        return None
    if tx.kind == "private_fee":
        return replace(state, consumed=state.consumed | {tx.source}, fees=state.fees + source.amount)
    if len(state.records) >= MAX_SLOTS or source.amount == 0:
        return None
    version = (1 if tx.kind == "legacy" else 2 if tx.kind == "prepare"
               else source.version if tx.kind == "rotate" else 3)
    key = "L" if tx.kind == "legacy" else tx.key
    if version >= 2:
        if key not in CATEGORY or key == "L":
            return None
        if check_pop and not tx.recipient_possession:
            return None
        if tx.kind == "migrate" and key != source.key:
            return None
        if check_category and CATEGORY[key] < CATEGORY[source.key]:
            return None
    record = Record(version, source.amount - 1, key)
    return replace(state, records=state.records + (record,),
                   consumed=state.consumed | {tx.source} if atomic else state.consumed,
                   fees=state.fees + 1)


def supply(state):
    return state.fees + sum(r.amount for i, r in enumerate(state.records) if i not in state.consumed)


def boundary_vectors():
    vectors = []
    for version in range(4):
        for kind in KINDS:
            for height in (H1 - 1, H1, H2 - 1, H2, H2 + 1):
                vectors.append({"input_version": version, "operation": kind,
                                "candidate_height": height,
                                "allowed_by_phase": allowed(version, kind, height)})
    # Production limits are independently specified, not inferred from outputs.
    cap = 1_000_000_000_000
    pool_cap = 4_000_000_000_000
    caps = [{"source_microcredits": amount, "pool_before": pool,
             "eligible": amount <= cap and pool + amount <= pool_cap}
            for amount in (cap - 1, cap, cap + 1)
            for pool in (0, pool_cap - cap, pool_cap - cap + 1)]
    return {"H1": H1, "H2": H2, "phase_vectors": vectors, "historical_cap_vectors": caps}


def explore():
    initial = State()
    seen = {initial}
    todo = deque([initial])
    edges = 0
    witnessed = {name: False for name in ("prepare_v0", "prepare_v1", "migrate", "spend", "rotate_v2", "rotate_v3")}
    while todo:
        state = todo.popleft()
        assert supply(state) == 6, state
        assert state.consumed <= set(range(len(state.records)))
        if state.height < H2:
            advanced = replace(state, height=state.height + 1)
            if advanced not in seen:
                seen.add(advanced)
                todo.append(advanced)
        for source, record in enumerate(state.records):
            for kind in KINDS:
                for key in KEYS:
                    tx = Tx(kind, source, key)
                    new = apply(state, tx)
                    if new is None:
                        continue
                    edges += 1
                    assert source not in state.consumed
                    assert supply(new) == supply(state)
                    assert len(new.consumed - state.consumed) == 1
                    assert kind not in ("legacy", "private_fee") or state.height + 1 < H1
                    assert apply(new, tx) is None  # copied nonce/effects cannot consume twice
                    assert apply(state, replace(tx, same_chain=False)) is None
                    assert apply(state, replace(tx, opening_member=False)) is None
                    assert apply(state, replace(tx, exact_effects=False)) is None
                    if record.version < 2:
                        assert apply(state, replace(tx, owner_authorized=False)) is None
                    else:
                        assert apply(state, replace(tx, input_authorized=False)) is None
                    if kind not in ("legacy", "private_fee"):
                        assert apply(state, replace(tx, recipient_possession=False)) is None
                    if kind == "prepare":
                        witnessed[f"prepare_v{record.version}"] = True
                    elif kind == "rotate":
                        witnessed[f"rotate_v{record.version}"] = True
                    elif kind in witnessed:
                        witnessed[kind] = True
                    if new not in seen:
                        seen.add(new)
                        todo.append(new)
    assert all(witnessed.values()), witnessed
    return {"states": len(seen), "accepted_edges": edges, "reachable": witnessed}


def mutation_checks():
    initial = State(height=H1 - 1)
    prep = Tx("prepare", 0)
    prepared = apply(initial, prep)
    assert prepared is not None
    changed = replace(prep, exact_effects=False)
    missing_pop = replace(prep, recipient_possession=False)
    assert apply(initial, changed) is None and apply(initial, changed, check_effects=False) is not None
    assert apply(initial, missing_pop) is None and apply(initial, missing_pop, check_pop=False) is not None
    repeated = apply(prepared, prep, check_spent=False)
    assert repeated is not None and supply(repeated) != 6
    torn = apply(initial, prep, atomic=False)
    assert torn is not None and supply(torn) != 6
    at_boundary = State(height=H1 - 1)
    assert apply(at_boundary, Tx("legacy", 0)) is None
    assert apply(at_boundary, Tx("legacy", 0), candidate_height=False) is not None
    strong = replace(initial, records=(Record(2, 3, "M0"), Record(1, 3, "L")))
    downgrade = Tx("rotate", 0, "F0")
    assert apply(strong, downgrade) is None
    assert apply(strong, downgrade, check_category=False) is not None
    # Migrate must retain the enrolled key, even at the same claimed category.
    migration = replace(initial, height=H2 - 1, records=(Record(2, 3, "F0"), Record(1, 3, "L")))
    assert apply(migration, Tx("migrate", 0, "F1")) is None
    assert apply(migration, Tx("migrate", 0, "F0")) is not None
    # A legacy-forging adversary after H2 cannot prepare a dormant source or
    # replace the enrolled authority, even with a disclosed authentic opening.
    compromised = State(height=H2 - 1)
    assert apply(compromised, Tx("prepare", 0, owner_authorized=True)) is None
    assert apply(migration, Tx("migrate", 0, "F0", owner_authorized=True,
                               input_authorized=False, opening_member=True)) is None
    # A copied nonce alone cannot reserve or consume a different input.
    distinct = apply(prepared, Tx("prepare", 1, "M0", nonce=prep.nonce))
    assert distinct is not None and distinct.consumed == frozenset((0, 1))
    assert supply(distinct) == 6
    # Rejected transitions preserve the exact original persistent snapshot.
    before = repr(prepared)
    assert apply(prepared, replace(prep, owner_authorized=False)) is None
    assert repr(prepared) == before
    # Crash/restart exposes the last complete committed snapshot. This is a
    # specification of the store obligation, not a process-kill/WAL experiment.
    disk = prepared
    live = replace(prepared, height=H2 - 1)
    assert live != disk
    live = disk
    assert live == prepared and supply(live) == 6
    return ["candidate_height", "shared_consumption", "atomic_visibility", "effect_binding",
            "recipient_possession", "category_downgrade", "migration_key_substitution",
            "legacy_compromise_after_window", "copied_nonce_distinct_input",
            "rejected_snapshot", "crash_to_committed_snapshot"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    results = {"scope": __doc__, "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "bounded_model": explore(), "mutation_checks": mutation_checks(),
               "seconds": round(time.monotonic() - started, 3)}
    vectors = boundary_vectors()
    (args.output / "boundary-vectors.json").write_text(json.dumps(vectors, indent=2) + "\n")
    # A minimal text format lets Rust compare the independent phase predicate
    # without introducing a parser dependency or importing model implementation.
    tsv = "input_version\toperation\tcandidate_height\tallowed_by_phase\n" + "".join(
        f"{v['input_version']}\t{v['operation']}\t{v['candidate_height']}\t{int(v['allowed_by_phase'])}\n"
        for v in vectors["phase_vectors"])
    (args.output / "disclosed-phase.tsv").write_text(tsv)
    results["phase_vectors_sha256"] = hashlib.sha256(tsv.encode()).hexdigest()
    results["boundary_vectors_sha256"] = hashlib.sha256((args.output / "boundary-vectors.json").read_bytes()).hexdigest()
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
