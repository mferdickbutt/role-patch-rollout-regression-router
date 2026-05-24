# Role Patch Rollout Regression Router

Deterministic post-apply reducer that consumes sanitized Hive Mind role-template rollout receipts and emits exactly one rollback or continuation decision per role.

## Quick Start

```bash
python3 role_patch_rollout_regression_router.py
```

Outputs a console table, 21 embedded assertions, and a deterministic JSON array of decisions. No external services, no private data, no dependencies beyond the Python standard library.

## Decisions

The reducer emits exactly one of these per role:

| Decision | Meaning |
|---|---|
| `keep_patch` | Clean. No flags, all checks pass. |
| `monitor_patch` | Low/medium severity flags detected, within tolerance. |
| `rollback_overbroad_output` | Patch touched roles outside its declared scope. |
| `rollback_verification_regression` | Post-apply verification checks failed. |
| `rollback_privacy_regression` | Privacy leak detected. |
| `rollback_duplicate_scope` | Same scope was already patched in this window. |
| `request_new_canary` | Canary validation failed; need a fresh canary run. |
| `reviewer_escalation` | Critical/multi-regression or unrecognized flag; human must review. |

## Input Schema

Each receipt is a sanitized post-apply record:

```
RolloutReceipt
├── case_id                  str          unique case identifier
├── role_id                  str          role template identifier
├── patch_id                 str          patch identifier
├── rollout_window           str          e.g. "2026-W21"
├── declared_scope           tuple[str]   roles the patch intended to modify
├── actual_affected_roles    tuple[str]   roles the patch actually modified
├── regression_flags         tuple[RegressionFlag]
│   ├── flag_type            str          e.g. "privacy_leak", "verification_failure", "scope_exceeded"
│   ├── severity             str          none / low / medium / high / critical
│   ├── scope_affected       tuple[str]   roles touched by this flag
│   └── reviewer_safe_detail str          human-readable, no private data
├── has_duplicate_scope      bool         another patch already covered this scope in this window
├── canary_valid             bool         pre-apply canary passed
├── verification_pass        bool         post-apply verification passed
├── privacy_pass             bool         post-apply privacy check passed
└── reviewer_safe_severity   str          overall severity summary
```

## Output Schema

The JSON output is a stable array:

```json
{
  "reducer": "role_patch_rollout_regression_router",
  "version": "1.0.0",
  "window": "2026-W21",
  "total_decisions": 14,
  "decision_checksum": "ed7ca6ef1799dd26",
  "decisions": [
    {
      "case_id": "CASE-0451",
      "role_id": "ROLE-moderator",
      "patch_id": "PATCH-a1b2c3",
      "decision": "keep_patch",
      "severity": "none",
      "reviewer_safe_reason": "No regression flags; all checks pass",
      "triggered_flags": ["all_checks_pass"],
      "scope_drift_count": 0
    }
  ]
}
```

Each decision contains `case_id`, `role_id`, `patch_id`, `decision`, `severity`, `reviewer_safe_reason`, `triggered_flags`, and `scope_drift_count`. The `decision_checksum` is a SHA-256 truncation over all case-decision pairs for tamper detection.

## Precedence Rules

When multiple conditions trigger simultaneously, precedence determines the final decision (highest priority first):

```
reviewer_escalation          (rank 0)
rollback_privacy_regression  (rank 1)
rollback_verification_regression (rank 2)
rollback_overbroad_output    (rank 3)
rollback_duplicate_scope     (rank 4)
request_new_canary           (rank 5)
monitor_patch                (rank 6)
keep_patch                   (rank 7)
```

The tiebreaker is `min(candidates, key=PRECEDENCE_RANK)` — lowest rank wins.

## How `_evaluate_single` Works

The core reducer function runs in seven phases per receipt:

### Phase 1 — Classify conditions

Each condition requires **both** a matching flag type **and** a failed check (dual-condition gate):

```
has_privacy      =  flag_type=="privacy_leak"       AND privacy_pass==False
has_verification =  flag_type=="verification_failure" AND verification_pass==False
has_overbroad    =  scope_drift_count > 0
has_dup          =  has_duplicate_scope == True
needs_canary     =  canary_valid == False
```

This prevents stale flags from triggering rollbacks on their own.

### Phase 2 — Collect specific rollback types

Builds a list of all triggered specific rollback types. Used by the multi-regression escalation check.

### Phase 3 — Escalation gating

Two escalation rules, checked in order:

1. **Critical + verification failure** → `reviewer_escalation`. When the verification system itself fails at critical severity, the system cannot self-diagnose — human review is mandatory.
2. **Critical + 2+ specific rollback types** → `reviewer_escalation`. Multiple simultaneous regressions at critical severity indicates systemic failure.

If escalation triggers, the function returns immediately with all triggered reasons listed for the audit trail.

### Phase 4 — Build candidate list

If no escalation, collect all applicable candidates from the specific rollback types, canary request, and the monitor block (LOW/MEDIUM severity only).

### Phase 5 — Fail-safe catch-all

```python
if not candidates and max_sev in (HIGH, CRITICAL):
    → reviewer_escalation
```

If a receipt carries a HIGH or CRITICAL flag with an unrecognized `flag_type` (e.g. `"data_corruption"`, `"schema_mismatch"`, anything not `privacy_leak`/`verification_failure`/`scope_exceeded`), and no specific condition matched, and the severity is too high for the monitor block, it escalates instead of falling through to `keep_patch`. This is **fail-closed**: unknown threats at high severity always get human review.

### Phase 6 — Default

If still no candidates (zero flags, all checks pass, severity NONE), emit `keep_patch`.

### Phase 7 — Tiebreak

```python
best = min(candidates, key=lambda c: PRECEDENCE_RANK[c[0]])
```

Deterministic: same input always produces the same output.

## Design Decisions

| Decision | Rationale |
|---|---|
| Fail-closed on unknown HIGH/CRITICAL | Unrecognized flag types escalate rather than pass through. Better to over-alert than to silently approve a broken patch. |
| Critical verification always escalates | When the verification system itself fails at critical, the system can't self-diagnose — human review is the only safe option. |
| Critical privacy does NOT auto-escalate | A known privacy leak has a clear remediation (rollback the patch), so it routes to the specific `rollback_privacy_regression` action instead of escalating. |
| Multi-regression at critical escalates | 2+ simultaneous rollback types at critical = systemic failure = human review. |
| Dual-condition gates | A flag alone isn't enough — the corresponding check must also fail. Prevents stale flags from triggering rollbacks. |
| Precedence-based tiebreaking | `PRECEDENCE_RANK` ensures the same multi-flag input always produces the same output regardless of insertion order. |

## Embedded Fixtures

14 fixtures covering all 8 decision branches:

| Fixture | Scenario | Expected |
|---|---|---|
| FX-001 | Clean receipt, no flags | `keep_patch` |
| FX-002 | Low severity `output_format_drift` | `monitor_patch` |
| FX-003 | `scope_exceeded` — 1 role beyond declared scope | `rollback_overbroad_output` |
| FX-004 | `verification_failure` at high severity | `rollback_verification_regression` |
| FX-005 | `privacy_leak` at critical, no verification failure | `rollback_privacy_regression` |
| FX-006 | `has_duplicate_scope=True`, no flags | `rollback_duplicate_scope` |
| FX-007 | `canary_valid=False`, no flags | `request_new_canary` |
| FX-008 | Critical verification + scope drift + privacy + invalid canary (multi-regression) | `reviewer_escalation` |
| FX-009 | Overbroad + duplicate scope + low drift (precedence test) | `rollback_overbroad_output` |
| FX-010 | Privacy (high) + verification (medium) — privacy wins by precedence | `rollback_privacy_regression` |
| FX-011 | Two low-severity flags | `monitor_patch` |
| FX-012 | Critical verification failure alone | `reviewer_escalation` |
| FX-013 | Unrecognized `data_corruption` flag at critical | `reviewer_escalation` |
| FX-014 | Unrecognized `schema_mismatch` flag at high | `reviewer_escalation` |

## Embedded Assertions

21 assertions run on every execution:

| # | Check |
|---|---|
| 1–14 | Each fixture's decision matches its `expected_decision` |
| 15 | Total decision count equals fixture count |
| 16 | All 8 decision types are represented (full branch coverage) |
| 17 | Every `reviewer_escalation` has severity `critical` or `high` |
| 18 | Every `rollback_privacy_regression` has `privacy_check_failed` in triggers |
| 19 | Every `rollback_overbroad_output` has `scope_drift_count > 0` |
| 20 | Every `keep_patch` has exactly `["all_checks_pass"]` as triggers |
| 21 | Exactly 2 unrecognized-flag escalation cases exist, both are `reviewer_escalation` |

Any assertion failure exits with code 1.

## Safety Constraints

This reducer uses **no** live Task Node exports, wallet-identifying data, private contributor notes, credentials, dashboards, proprietary finance data, or real user-level evidence. All fixtures are synthetic. All `reviewer_safe_detail` fields contain reviewer-safe descriptions only.

## Version

`1.0.0` — Window `2026-W21`
