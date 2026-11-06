# Native credits VM validation

Run from the core snarkVM checkout. Source identities and the tested binary hash
are in `production-vm-evidence.json`. This local test schedule does not schedule
either public activation.

```sh
source /workspace/.setup/snarkos-env.sh
PARAM_DIR="$(mktemp -d /workspace/recovery-parameters.XXXXXX)"
python3 recovery/history-tools/prefetch-parameters.py --output "$PARAM_DIR"
python3 - "$PARAM_DIR" <<'PY'
import hashlib, json, pathlib, shutil, sys
staging = pathlib.Path(sys.argv[1])
cache = pathlib.Path.home() / '.aleo' / 'resources'
cache.mkdir(parents=True, exist_ok=True)
for item in json.loads((staging / 'prefetch-manifest.json').read_text())['files']:
    source = staging / item['file']
    data = source.read_bytes()
    assert len(data) == item['bytes']
    assert hashlib.sha256(data).hexdigest() == item['sha256']
    destination = cache / item['file']
    shutil.copyfile(source, destination)
    destination.chmod(0o600)
PY
CARGO_INCREMENTAL=0 \
CARGO_TARGET_DIR=/workspace/snarkOS/target \
RUSTFLAGS='-C target-cpu=skylake' \
CONSENSUS_VERSION_HEIGHTS='0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,30,40' \
cargo test --locked -p snarkvm-synthesizer --features test,dev-print \
  --lib vm::recovery_tests:: -- --include-ignored --nocapture --test-threads=1
```

The parameter installation writes only verified public classical proving files
to the standard Aleo cache. It preserves TLS and full parameter-hash checks.
These files support the historical record-creating executions; native V2/V3
authorization does not wrap a classical ownership proof in a PQ signature.

The retained build first passed the V0 compatibility test and then encountered
missing classical parameters. `historical-v0-vm-mixed.log` preserves that run and
its explicit failure. After verified cache initialization, the unchanged
compiled binary passed the complete native V1 preparation/migration/spending
test; its exact output is `production-vm-success.log`.

The focused test covers both boundaries, competing legacy/native spends,
post-enrollment legacy-key compromise, changed effects and keys, a forged serial,
replay, historical-pool limits, fee conservation, aborted finalization, stored
VM reconstruction and native spends chained within one block. Four-validator
and process-kill storage evidence are separate acceptance checks.

The exact previously tested libtest executable is now losslessly retained as
`/workspace/security-evaluation/disclosed-recovery-20261022/prior-production-vm-libtest.gz`.
Its original target path was removed to reclaim build space. The archive metadata
and verified decompression hashes are in
[`checks/prior-production-vm-libtest-archive.json`](checks/prior-production-vm-libtest-archive.json).
A safe temporary restoration is:

```sh
gzip -dc /workspace/security-evaluation/disclosed-recovery-20261022/prior-production-vm-libtest.gz > /tmp/snarkvm-prior-libtest
chmod 700 /tmp/snarkvm-prior-libtest
sha256sum /tmp/snarkvm-prior-libtest
```

The restored SHA256 must be
`a289eb3facbd4525838cdbe715d636f026a8027985fad38d68de6ca966ace6fb`.
This executable reproduces prior-candidate evidence, not the later membership fix.
The source command above builds the matching checkout; fresh source-matched
runtime results remain separate.
