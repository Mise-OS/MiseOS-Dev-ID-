# Agent Integration Control Plane

This layer connects repository automation and research/observability tools without moving security authority outside the MiseOS verifier.

## Operating model

```text
Agent / Coordinator
        |
        v
Constrained orchestration
        |
        v
Capability adapters
        |
        +--> GitHub
        +--> CodeRabbit
        +--> Parallel Search
        +--> Post Metadata Extractor
        +--> Hugging Face
        +--> Amplitude
        |
        v
MiseOS policy + authorization boundary
        |
        v
ALLOW | DENY | INDETERMINATE
```

The coordinator may plan work, Code Mode may batch safe read/compute operations, and review/research tools may supply evidence. None of those layers can redefine the final authorization decision.

## Integration roles

| Integration | Initial role | Safe through constrained orchestration | Restricted operations |
|---|---|---|---|
| GitHub | source, CI, PRs, provenance | repository reads, status, diffs, issue/PR inspection | writes, merges, branch protection, releases |
| CodeRabbit | code review | review findings and review context | automatic mutation/merge |
| Codex Coordinator | work orchestration | planning, task decomposition, sequencing | recursive authority escalation |
| Parallel Search | external retrieval | batched research and source collection | none by default |
| Post Metadata Extractor | deterministic transformation | metadata extraction/normalization | none |
| Hugging Face | model/data research | model/dataset metadata and research | model deployment or credential changes |
| Amplitude | observability | analytics queries and trend summaries | telemetry mutations that could influence authorization |

## Security invariants

1. **Tool access is not authority.** A connector can return data without being able to authorize an action.
2. **Evidence is not a decision.** Search, analytics, model metadata, and code review remain supporting evidence.
3. **Generated code is untrusted.** Code Mode receives only narrow capability adapters, never raw privileged clients.
4. **Production mutations stay outside orchestration.** Destructive, signing, deployment, permission, revocation, and authorization changes require a direct policy-controlled path.
5. **Fail closed.** `INDETERMINATE` is never promoted to `ALLOW`.
6. **Audit everything consequential.** Record actor, capability, scope, resource, input digest, result class, policy decision, and provenance metadata.

## Next implementation slice

- Add typed adapter interfaces under `src/integrations/`.
- Add Zod/JSON-schema-equivalent validation at every adapter boundary.
- Add provenance envelopes for external evidence.
- Add deterministic fixtures for allowed, denied, and indeterminate adapter requests.
- Wire CodeRabbit review into pull-request CI without granting it authority to merge.
- Add coordinator manifests only after the capability boundary is executable and tested.
