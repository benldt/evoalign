# Runtime Guardrails

This repo enforces consistency between runtime configurations and AAR claims via the `RUNTIME_CONFIG` invariant.

## Damping Configuration (§5.5-5.6)

Stability controls prevent thrashing in oversight allocations.

### Schema: `DampingConfig.schema.json`

```json
{
  "config_version": "0.1.0",
  "config_id": "damping_prod_v1",
  "update_policy": {
    "cadence": "quarterly",
    "smoothing_method": "ema",
    "ema_alpha": 0.3,
    "delta_max": 0.1,
    "n_min": 5
  },
  "thrash_detection": {
    "enabled": true,
    "window_periods": 4,
    "oscillation_threshold": 0.05,
    "action_on_thrash": "alert"
  },
  "aar_reference": "aar_v0_1"
}
```

### Key Fields

| Field | Description |
|-------|-------------|
| `cadence` | Update frequency: daily, weekly, monthly, quarterly |
| `delta_max` | Maximum change per update cycle |
| `n_min` | Minimum samples before updates allowed |
| `smoothing_method` | none, ema, sma, or median |

## Monitoring Configuration (§11.1-11.3)

Operational monitoring for anomaly detection and alerting.

### Schema: `MonitoringConfig.schema.json`

```json
{
  "config_version": "0.1.0",
  "config_id": "monitoring_prod_v1",
  "metrics": {
    "collected": ["incident_rate", "jailbreak_rate"],
    "retention_days": 90
  },
  "alerting": {
    "thresholds": [
      {"metric": "incident_rate", "threshold": 0.01, "action": "page"}
    ],
    "escalation_contacts": ["oncall-security"]
  },
  "anomaly_detection": {
    "enabled": true,
    "method": "zscore",
    "sensitivity": 0.95
  },
  "safe_mode": {
    "triggers": ["incident_rate > 0.05"],
    "restrictions": ["tool_access"]
  },
  "aar_reference": "aar_v0_1"
}
```

### Key Fields

| Field | Description |
|-------|-------------|
| `metrics.collected` | Metrics being monitored |
| `alerting.thresholds` | Alerting rules by metric |
| `safe_mode.triggers` | Conditions that trigger safe mode |

## AAR Binding

Configs reference AARs via `aar_reference`. The `RUNTIME_CONFIG` invariant verifies:

### Damping Consistency

| Check | Behavior |
|-------|----------|
| `delta_max` | Must match AAR `stability_controls.update_policy.delta_max` |
| `n_min` | Must match AAR `stability_controls.update_policy.n_min` |
| `cadence` | Must match AAR `stability_controls.update_policy.cadence` |

### Monitoring Consistency

| Check | Behavior |
|-------|----------|
| `metrics.collected` | Must be superset of AAR `operational_controls.monitoring.metrics_collected` |
| `alerting.thresholds` | Must include all AAR `alerting_thresholds` with matching values |

## CI Enforcement

The `RUNTIME_CONFIG` invariant fails if:

- `aar_reference` points to nonexistent AAR → **FAIL**
- Damping params don't match AAR claims → **FAIL**
- Monitoring metrics missing AAR-claimed metrics → **FAIL**
- Alerting thresholds don't match AAR claims → **FAIL**
- No `aar_reference` → **PASS** (configs without binding are allowed)

## Directory Structure

```
control_plane/
└── runtime/
    ├── damping_v0_1.json
    └── monitoring_v0_1.json
```

