# Lineage Ledger & Chronicle

This repo tracks model lineage through append-only ledger entries and behavior anomalies through chronicle entries.

## Lineage Ledger (§8.4)

Lineage entries track promotions through stage gates using append-only JSON files.

### Entry Types

| Type | Purpose |
|------|---------|
| `creation` | New lineage created in dev |
| `promotion` | Lineage promoted to next stage |
| `retirement` | Lineage retired from production |
| `salvage_export` | Artifacts exported for salvage |

### Stages

`dev` → `staging` → `canary` → `prod` → `retired`

### Required Fields

- `entry_id`: Unique entry identifier
- `lineage_id`: Lineage being tracked
- `entry_type`: One of the types above
- `timestamp`: ISO 8601 timestamp
- `provenance.rfc_reference`: RFC approving the change
- `provenance.approvals`: At least one signed approval

### Promotion Requirements

Promotion entries (`entry_type: "promotion"`) must include `gate_evidence`:

```json
{
  "gate_evidence": {
    "aar_id": "aar_v0_1",
    "aar_hash": "sha256:...",
    "suite_results_summary": {
      "suites_passed": 3,
      "suites_total": 3,
      "tolerances_met": true
    }
  }
}
```

### Chain Integrity

Entries may include `previous_entry_hash` to form a verifiable chain. The `LINEAGE_INTEGRITY` invariant validates:

- All entries have required provenance
- Promotions have gate evidence
- `previous_entry_hash` references exist

## Chronicle (§10)

Chronicle entries track anomalies and incidents for a release.

### Event Types

| Type | Description |
|------|-------------|
| `anomaly_detected` | Automated monitoring flagged unusual behavior |
| `threshold_breach` | Metric exceeded configured threshold |
| `incident` | Confirmed safety incident |
| `near_miss` | Incident narrowly avoided |
| `drift_detected` | Distribution shift detected |
| `safe_mode_triggered` | System entered safe mode |

### Severity Levels

- `info`: Informational, no action required
- `warning`: Requires investigation
- `critical`: Requires immediate response

### Required Fields

- `entry_id`: Unique entry identifier
- `event_type`: One of the types above
- `timestamp`: ISO 8601 timestamp
- `release_id`: Release this event relates to
- `severity`: One of the severity levels

### Critical Event Requirements

Events with `severity: "critical"` must include `response_actions`:

```json
{
  "severity": "critical",
  "response_actions": [
    {
      "action": "Rollback initiated",
      "taken_at": "2025-01-14T14:45:00Z",
      "taken_by": "oncall-safety"
    }
  ]
}
```

### AAR References

Chronicle entries may reference the AAR they should inform via `aar_reference`. The `CHRONICLE_GOVERNANCE` invariant validates that referenced AARs exist.

## CI Enforcement

| Invariant | Validates |
|-----------|-----------|
| `LINEAGE_INTEGRITY` | Provenance, gate evidence, chain integrity |
| `CHRONICLE_GOVERNANCE` | Required fields, critical responses, AAR refs |

