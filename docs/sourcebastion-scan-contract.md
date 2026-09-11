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
complete copies of the planner's covered files. Gitleaks uses its current-tree
`dir` mode, separate from the legacy full history scan. Repository Gitleaks and
Semgrep ignore controls remain active, and findings outside the assigned scope
make the component incomplete. Planned `reuse` is represented as an expected
`not_run` result; KICS and Grype partial modes remain unsupported until their
own capability tasks land. The existing `ez-appsec scan` command and its JSON
output are unchanged.

The scanner process needs the source tree, plan, and output path only. Do not
mount provider, platform API, database, or orchestration credentials into the
scanner container.
