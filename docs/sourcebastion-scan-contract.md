# SourceBastion scan contract

`contract-scan` is the portable M036 boundary used by hosted executors and
customer CI. It accepts a trusted, canonical `sourcebastion.scan-plan.v1` JSON
file and writes a canonical `sourcebastion.scan-result.v1` envelope.

```bash
ez-appsec contract-scan /workspace/source \
  --plan /workspace/input/scan-plan.json \
  --result-envelope /workspace/output/scan-result.json \
  --scanner-image \
    ghcr.io/ez-appsec/ez-appsec@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

`--scanner-image` may instead be supplied through
`EZ_APPSEC_SCANNER_IMAGE`. It must be the immutable digest in the plan. The
checkout's locally observed Git `HEAD` must also equal the plan's exact head.

The command validates the plan version, canonical digest, identities, baseline
proof, component compatibility keys, modes, scopes, and declared limits before
running a scanner. It rejects traversal and ambiguous paths, oversized plans or
source trees, stale baseline proofs, and mismatched checkout or image identity.
Output is written atomically and includes one result for every planned
component, the observed head, plan and image binding, bounded status and
diagnostic codes, timestamps, and a canonical envelope digest.

S03/T03 supports partial Gitleaks, Semgrep, and custom-PHP execution against
complete copies of the planner's covered files. Contract full and partial
Gitleaks execution both use current-tree `dir` mode so scoped replacement is
equivalent to full coverage. The legacy `ez-appsec scan` command retains its
separate Git-history scan. Repository Gitleaks and Semgrep ignore controls
remain active, and findings outside the assigned scope make the component
incomplete. Planned `reuse` is represented as an expected `not_run` result;
S03/T04 adds KICS execution over complete planned IaC files or directories.
Local Terraform module references must resolve inside the planned unit set;
unresolved or out-of-scope references report `scope_unresolved` so the trusted
platform can schedule a full fallback. Grype has no partial mode: a planned
partial Grype component reports `not_run` with `unsupported_mode`. The existing
`ez-appsec scan` JSON output is unchanged.

S03/T05 binds Grype reuse to the image's runtime identity. `ez-appsec
contract-identity --scanner-image <ref@sha256:…> --output identity.json` writes
a `sourcebastion.scanner-identity.v1` document describing every contract
component: tool versions, bundled rule digests for Semgrep, KICS and the custom
PHP scanner, and for Grype the Syft version, vulnerability database schema,
built time and archive checksum, plus digests of the cataloguing and policy
subsets of the effective Grype configuration read from a neutral directory. The
trusted platform pins that document per image digest and fingerprints
compatibility keys from it. A plan component may carry an optional `identity`
object echoing those values; the scanner recomputes its runtime identity and
reports `failed` with `identity_mismatch` (drifted runtime, for example a
refreshed advisory database) or `identity_unavailable` before running or
skipping the component. A Grype `reuse` component must pin every Grype identity
field or it reports `failed` with `identity_unbound`; the result validator
rejects an envelope that claims an unbound Grype reuse as `not_run`. Reuse of
any other component is unaffected. The identity document and the `identity`
plan field are additive to plan v1 and never change the envelope shape.

S03/T06 caps each finding, total finding metadata, metadata depth, and the final
result envelope. Duplicate logical findings and malformed core finding fields
make the component incomplete. A component interrupted by cancellation records
`failed` with the bounded `cancelled` diagnostic and still produces a complete
result envelope for the trusted fallback path. The plan's execution deadline is
also propagated to scanner discovery, preparation, database refreshes, and tool
processes so a component's larger built-in timeout cannot overrun the plan.

The scanner process needs the source tree, plan, and output path only. Do not
mount provider, platform API, database, or orchestration credentials into the
scanner container.
