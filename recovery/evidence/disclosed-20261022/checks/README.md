# Validation evidence

`results.json` is the explicit public-artifact whitelist, with SHA256 identities and byte counts.
No node directories, wallet files or account/PQ signing secrets are copied.

The final optimized node is identified by `cost-boundary-node-build-after.json` and its
immutable build-source snapshot. `native-final-summary.json` records 12 accepted native
transactions, 21 negative cases across four validators, both activations, persistence,
interrupted finalization, observed partition/reconnection and checked snapshot replay.
A two-client relay ends with all six nodes agreeing on `native-final-state.json`;
`native-final-decoded-checkpoint.json` independently decodes the same accounting.

The native result is composed: the first corrected run hit HTTP429 on its last
post-rollback transaction read. Its original failed result remains external and is hash-bound
in the summary. A bounded read-only retry and explicit continuation revalidated all accepted
bodies, state and boundary hashes before client relay. It did not regenerate proofs or migrations.
`relay-resume-harness-tests.log` records ten passing harness regressions.

`ci-final-optimized-results.json` records unchanged ordinary CI PASS (208.19 s),
all eight nodes and original logfile caps. `ci-final-optimized-summary.log` redacts development
key strings. Raw CI logs remain external.

Earlier logs remain component/prior-candidate evidence with their original outcomes:
ordinary debug CI exceeded its 2 MiB log cap; an optimized native attempt exposed a real
H1 proposer-cost bug. `native-cost-boundary-failure.json` and the red/green regression
preserve that finding. Pure resource estimation no longer gates activation;
candidate-height VM authorization still does. New four-worktree strict checks pass.

Source manifests and full source archives distinguish base commits, dirty source overlays,
compiled Rust inputs and script versions. Archived older binaries have explicit restore metadata;
they are not substituted for the final binary. For architecture, costs, commands and remaining
cryptographic/checkpoint/scaling obligations, see [the report](../../../../RECOVERY_RESULTS.md).
