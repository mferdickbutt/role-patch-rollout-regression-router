#!/usr/bin/env python3
"""
role_patch_rollout_regression_router.py — Role Patch Rollout Regression Router

Consumes sanitized post-apply Hive Mind role-template rollout receipts and
emits exactly one deterministic decision per role from the post-apply surface:

  keep_patch, monitor_patch, rollback_overbroad_output,
  rollback_verification_regression, rollback_privacy_regression,
  rollback_duplicate_scope, request_new_canary, reviewer_escalation

Precedence (highest first):
  reviewer_escalation > rollback_privacy_regression >
  rollback_verification_regression > rollback_overbroad_output >
  rollback_duplicate_scope > request_new_canary > monitor_patch > keep_patch

Run:  python3 role_patch_rollout_regression_router.py
Expect: console table + embedded assertions + deterministic JSON output.
"""

import json
import hashlib
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple


REDUCER_VERSION = "1.0.0"
DEFAULT_WINDOW = "2026-W21"


class Decision(str, Enum):
    KEEP_PATCH = "keep_patch"
    MONITOR_PATCH = "monitor_patch"
    ROLLBACK_OVERBROAD_OUTPUT = "rollback_overbroad_output"
    ROLLBACK_VERIFICATION_REGRESSION = "rollback_verification_regression"
    ROLLBACK_PRIVACY_REGRESSION = "rollback_privacy_regression"
    ROLLBACK_DUPLICATE_SCOPE = "rollback_duplicate_scope"
    REQUEST_NEW_CANARY = "request_new_canary"
    REVIEWER_ESCALATION = "reviewer_escalation"


PRECEDENCE: List[Decision] = [
    Decision.REVIEWER_ESCALATION,
    Decision.ROLLBACK_PRIVACY_REGRESSION,
    Decision.ROLLBACK_VERIFICATION_REGRESSION,
    Decision.ROLLBACK_OVERBROAD_OUTPUT,
    Decision.ROLLBACK_DUPLICATE_SCOPE,
    Decision.REQUEST_NEW_CANARY,
    Decision.MONITOR_PATCH,
    Decision.KEEP_PATCH,
]

PRECEDENCE_RANK = {d: i for i, d in enumerate(PRECEDENCE)}


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class RegressionFlag:
    flag_type: str
    severity: str
    scope_affected: Tuple[str, ...]
    reviewer_safe_detail: str


@dataclass(frozen=True)
class RolloutReceipt:
    case_id: str
    role_id: str
    patch_id: str
    rollout_window: str
    declared_scope: Tuple[str, ...]
    actual_affected_roles: Tuple[str, ...]
    regression_flags: Tuple[RegressionFlag, ...]
    has_duplicate_scope: bool
    canary_valid: bool
    verification_pass: bool
    privacy_pass: bool
    reviewer_safe_severity: str


@dataclass
class RoleDecision:
    case_id: str
    role_id: str
    patch_id: str
    decision: str
    severity: str
    reviewer_safe_reason: str
    triggered_flags: List[str]
    scope_drift_count: int


FIXTURES: List[Dict[str, Any]] = [
    {
        "fixture_id": "FX-001-clean-keep",
        "receipt": {
            "case_id": "CASE-0451",
            "role_id": "ROLE-moderator",
            "patch_id": "PATCH-a1b2c3",
            "rollout_window": "2026-W21",
            "declared_scope": ("moderator",),
            "actual_affected_roles": ("moderator",),
            "regression_flags": (),
            "has_duplicate_scope": False,
            "canary_valid": True,
            "verification_pass": True,
            "privacy_pass": True,
            "reviewer_safe_severity": "none",
        },
        "expected_decision": Decision.KEEP_PATCH,
    },
    {
        "fixture_id": "FX-002-monitor-low-severity",
        "receipt": {
            "case_id": "CASE-0452",
            "role_id": "ROLE-contributor",
            "patch_id": "PATCH-d4e5f6",
            "rollout_window": "2026-W21",
            "declared_scope": ("contributor",),
            "actual_affected_roles": ("contributor",),
            "regression_flags": (
                {
                    "flag_type": "output_format_drift",
                    "severity": "low",
                    "scope_affected": ("contributor",),
                    "reviewer_safe_detail": "Minor output format variation within tolerance",
                },
            ),
            "has_duplicate_scope": False,
            "canary_valid": True,
            "verification_pass": True,
            "privacy_pass": True,
            "reviewer_safe_severity": "low",
        },
        "expected_decision": Decision.MONITOR_PATCH,
    },
    {
        "fixture_id": "FX-003-overbroad-output",
        "receipt": {
            "case_id": "CASE-0453",
            "role_id": "ROLE-validator",
            "patch_id": "PATCH-g7h8i9",
            "rollout_window": "2026-W21",
            "declared_scope": ("validator",),
            "actual_affected_roles": ("validator", "reviewer"),
            "regression_flags": (
                {
                    "flag_type": "scope_exceeded",
                    "severity": "high",
                    "scope_affected": ("validator", "reviewer"),
                    "reviewer_safe_detail": "Patch modified reviewer role output beyond declared validator scope",
                },
            ),
            "has_duplicate_scope": False,
            "canary_valid": True,
            "verification_pass": True,
            "privacy_pass": True,
            "reviewer_safe_severity": "high",
        },
        "expected_decision": Decision.ROLLBACK_OVERBROAD_OUTPUT,
    },
    {
        "fixture_id": "FX-004-verification-regression",
        "receipt": {
            "case_id": "CASE-0454",
            "role_id": "ROLE-auditor",
            "patch_id": "PATCH-j0k1l2",
            "rollout_window": "2026-W21",
            "declared_scope": ("auditor",),
            "actual_affected_roles": ("auditor",),
            "regression_flags": (
                {
                    "flag_type": "verification_failure",
                    "severity": "high",
                    "scope_affected": ("auditor",),
                    "reviewer_safe_detail": "Post-apply verification check failed for auditor role template",
                },
            ),
            "has_duplicate_scope": False,
            "canary_valid": True,
            "verification_pass": False,
            "privacy_pass": True,
            "reviewer_safe_severity": "high",
        },
        "expected_decision": Decision.ROLLBACK_VERIFICATION_REGRESSION,
    },
    {
        "fixture_id": "FX-005-privacy-regression",
        "receipt": {
            "case_id": "CASE-0455",
            "role_id": "ROLE-triage",
            "patch_id": "PATCH-m3n4o5",
            "rollout_window": "2026-W21",
            "declared_scope": ("triage",),
            "actual_affected_roles": ("triage",),
            "regression_flags": (
                {
                    "flag_type": "privacy_leak",
                    "severity": "critical",
                    "scope_affected": ("triage",),
                    "reviewer_safe_detail": "Post-apply output exposed internal routing metadata",
                },
            ),
            "has_duplicate_scope": False,
            "canary_valid": True,
            "verification_pass": True,
            "privacy_pass": False,
            "reviewer_safe_severity": "critical",
        },
        "expected_decision": Decision.ROLLBACK_PRIVACY_REGRESSION,
    },
    {
        "fixture_id": "FX-006-duplicate-scope",
        "receipt": {
            "case_id": "CASE-0456",
            "role_id": "ROLE-enforcer",
            "patch_id": "PATCH-p6q7r8",
            "rollout_window": "2026-W21",
            "declared_scope": ("enforcer",),
            "actual_affected_roles": ("enforcer",),
            "regression_flags": (),
            "has_duplicate_scope": True,
            "canary_valid": True,
            "verification_pass": True,
            "privacy_pass": True,
            "reviewer_safe_severity": "medium",
        },
        "expected_decision": Decision.ROLLBACK_DUPLICATE_SCOPE,
    },
    {
        "fixture_id": "FX-007-request-canary",
        "receipt": {
            "case_id": "CASE-0457",
            "role_id": "ROLE-curator",
            "patch_id": "PATCH-s9t0u1",
            "rollout_window": "2026-W21",
            "declared_scope": ("curator",),
            "actual_affected_roles": ("curator",),
            "regression_flags": (),
            "has_duplicate_scope": False,
            "canary_valid": False,
            "verification_pass": True,
            "privacy_pass": True,
            "reviewer_safe_severity": "medium",
        },
        "expected_decision": Decision.REQUEST_NEW_CANARY,
    },
    {
        "fixture_id": "FX-008-reviewer-escalation",
        "receipt": {
            "case_id": "CASE-0458",
            "role_id": "ROLE-governor",
            "patch_id": "PATCH-v2w3x4",
            "rollout_window": "2026-W21",
            "declared_scope": ("governor",),
            "actual_affected_roles": ("governor", "admin", "reviewer"),
            "regression_flags": (
                {
                    "flag_type": "scope_exceeded",
                    "severity": "critical",
                    "scope_affected": ("governor", "admin", "reviewer"),
                    "reviewer_safe_detail": "Patch affected 3 roles including admin; requires manual review",
                },
                {
                    "flag_type": "verification_failure",
                    "severity": "critical",
                    "scope_affected": ("governor",),
                    "reviewer_safe_detail": "Verification check failed on governor post-apply",
                },
            ),
            "has_duplicate_scope": False,
            "canary_valid": False,
            "verification_pass": False,
            "privacy_pass": False,
            "reviewer_safe_severity": "critical",
        },
        "expected_decision": Decision.REVIEWER_ESCALATION,
    },
    {
        "fixture_id": "FX-009-multi-flag-precedence",
        "receipt": {
            "case_id": "CASE-0459",
            "role_id": "ROLE-sentinel",
            "patch_id": "PATCH-y5z6a7",
            "rollout_window": "2026-W21",
            "declared_scope": ("sentinel",),
            "actual_affected_roles": ("sentinel", "watchman"),
            "regression_flags": (
                {
                    "flag_type": "scope_exceeded",
                    "severity": "high",
                    "scope_affected": ("sentinel", "watchman"),
                    "reviewer_safe_detail": "Patch touched watchman role outside declared scope",
                },
                {
                    "flag_type": "output_format_drift",
                    "severity": "low",
                    "scope_affected": ("sentinel",),
                    "reviewer_safe_detail": "Minor format drift on sentinel output",
                },
            ),
            "has_duplicate_scope": True,
            "canary_valid": True,
            "verification_pass": True,
            "privacy_pass": True,
            "reviewer_safe_severity": "high",
        },
        "expected_decision": Decision.ROLLBACK_OVERBROAD_OUTPUT,
    },
    {
        "fixture_id": "FX-010-privacy-over-verification",
        "receipt": {
            "case_id": "CASE-0460",
            "role_id": "ROLE-archivist",
            "patch_id": "PATCH-b8c9d0",
            "rollout_window": "2026-W21",
            "declared_scope": ("archivist",),
            "actual_affected_roles": ("archivist",),
            "regression_flags": (
                {
                    "flag_type": "privacy_leak",
                    "severity": "high",
                    "scope_affected": ("archivist",),
                    "reviewer_safe_detail": "Archivist output revealed internal indexing paths",
                },
                {
                    "flag_type": "verification_failure",
                    "severity": "medium",
                    "scope_affected": ("archivist",),
                    "reviewer_safe_detail": "Verification spot-check missed one sub-template",
                },
            ),
            "has_duplicate_scope": False,
            "canary_valid": True,
            "verification_pass": False,
            "privacy_pass": False,
            "reviewer_safe_severity": "high",
        },
        "expected_decision": Decision.ROLLBACK_PRIVACY_REGRESSION,
    },
    {
        "fixture_id": "FX-011-monitor-multiple-low",
        "receipt": {
            "case_id": "CASE-0461",
            "role_id": "ROLE-indexer",
            "patch_id": "PATCH-e1f2g3",
            "rollout_window": "2026-W21",
            "declared_scope": ("indexer",),
            "actual_affected_roles": ("indexer",),
            "regression_flags": (
                {
                    "flag_type": "output_format_drift",
                    "severity": "low",
                    "scope_affected": ("indexer",),
                    "reviewer_safe_detail": "Formatting whitespace changed in indexer output",
                },
                {
                    "flag_type": "timing_drift",
                    "severity": "low",
                    "scope_affected": ("indexer",),
                    "reviewer_safe_detail": "Processing latency increased 50ms within tolerance",
                },
            ),
            "has_duplicate_scope": False,
            "canary_valid": True,
            "verification_pass": True,
            "privacy_pass": True,
            "reviewer_safe_severity": "low",
        },
        "expected_decision": Decision.MONITOR_PATCH,
    },
    {
        "fixture_id": "FX-012-critical-escalation",
        "receipt": {
            "case_id": "CASE-0462",
            "role_id": "ROLE-reviewer",
            "patch_id": "PATCH-h4i5j6",
            "rollout_window": "2026-W21",
            "declared_scope": ("reviewer",),
            "actual_affected_roles": ("reviewer",),
            "regression_flags": (
                {
                    "flag_type": "verification_failure",
                    "severity": "critical",
                    "scope_affected": ("reviewer",),
                    "reviewer_safe_detail": "Critical verification regression on reviewer role template",
                },
            ),
            "has_duplicate_scope": False,
            "canary_valid": True,
            "verification_pass": False,
            "privacy_pass": True,
            "reviewer_safe_severity": "critical",
        },
        "expected_decision": Decision.REVIEWER_ESCALATION,
    },
    {
        "fixture_id": "FX-013-unrecognized-critical-flag",
        "receipt": {
            "case_id": "CASE-0463",
            "role_id": "ROLE-scout",
            "patch_id": "PATCH-k7l8m9",
            "rollout_window": "2026-W21",
            "declared_scope": ("scout",),
            "actual_affected_roles": ("scout",),
            "regression_flags": (
                {
                    "flag_type": "data_corruption",
                    "severity": "critical",
                    "scope_affected": ("scout",),
                    "reviewer_safe_detail": "Unknown flag type: post-apply data integrity anomaly on scout role",
                },
            ),
            "has_duplicate_scope": False,
            "canary_valid": True,
            "verification_pass": True,
            "privacy_pass": True,
            "reviewer_safe_severity": "critical",
        },
        "expected_decision": Decision.REVIEWER_ESCALATION,
    },
    {
        "fixture_id": "FX-014-unrecognized-high-flag",
        "receipt": {
            "case_id": "CASE-0464",
            "role_id": "ROLE-patrol",
            "patch_id": "PATCH-n0o1p2",
            "rollout_window": "2026-W21",
            "declared_scope": ("patrol",),
            "actual_affected_roles": ("patrol",),
            "regression_flags": (
                {
                    "flag_type": "schema_mismatch",
                    "severity": "high",
                    "scope_affected": ("patrol",),
                    "reviewer_safe_detail": "Unknown flag type: output schema drifted from expected template on patrol",
                },
            ),
            "has_duplicate_scope": False,
            "canary_valid": True,
            "verification_pass": True,
            "privacy_pass": True,
            "reviewer_safe_severity": "high",
        },
        "expected_decision": Decision.REVIEWER_ESCALATION,
    },
]


def _parse_receipt(raw: Dict[str, Any]) -> RolloutReceipt:
    flags = []
    for f in raw.get("regression_flags", []):
        flags.append(RegressionFlag(
            flag_type=f["flag_type"],
            severity=f["severity"],
            scope_affected=tuple(f["scope_affected"]),
            reviewer_safe_detail=f["reviewer_safe_detail"],
        ))
    return RolloutReceipt(
        case_id=raw["case_id"],
        role_id=raw["role_id"],
        patch_id=raw["patch_id"],
        rollout_window=raw["rollout_window"],
        declared_scope=tuple(raw.get("declared_scope", ())),
        actual_affected_roles=tuple(raw.get("actual_affected_roles", ())),
        regression_flags=tuple(flags),
        has_duplicate_scope=raw.get("has_duplicate_scope", False),
        canary_valid=raw.get("canary_valid", True),
        verification_pass=raw.get("verification_pass", True),
        privacy_pass=raw.get("privacy_pass", True),
        reviewer_safe_severity=raw.get("reviewer_safe_severity", "none"),
    )


def _max_severity(flags: Tuple[RegressionFlag, ...]) -> Severity:
    best = Severity.NONE
    for f in flags:
        s = Severity(f.severity)
        if SEVERITY_ORDER[s] > SEVERITY_ORDER[best]:
            best = s
    return best


def _scope_drift_count(receipt: RolloutReceipt) -> int:
    declared = set(receipt.declared_scope)
    actual = set(receipt.actual_affected_roles)
    return len(actual - declared)


def _evaluate_single(receipt: RolloutReceipt) -> Tuple[Decision, List[str], str]:
    reasons: List[str] = []
    max_sev = _max_severity(receipt.regression_flags)

    has_privacy = (
        not receipt.privacy_pass
        and any(f.flag_type == "privacy_leak" for f in receipt.regression_flags)
    )
    has_verification = (
        not receipt.verification_pass
        and any(f.flag_type == "verification_failure" for f in receipt.regression_flags)
    )
    drift = _scope_drift_count(receipt)
    has_overbroad = drift > 0
    has_dup = receipt.has_duplicate_scope
    needs_canary = not receipt.canary_valid

    specific_types: List[Decision] = []
    if has_privacy:
        specific_types.append(Decision.ROLLBACK_PRIVACY_REGRESSION)
    if has_verification:
        specific_types.append(Decision.ROLLBACK_VERIFICATION_REGRESSION)
    if has_overbroad:
        specific_types.append(Decision.ROLLBACK_OVERBROAD_OUTPUT)
    if has_dup:
        specific_types.append(Decision.ROLLBACK_DUPLICATE_SCOPE)

    escalate = False
    escalate_reason = ""
    if max_sev == Severity.CRITICAL and has_verification:
        escalate = True
        escalate_reason = "Critical severity with verification regression triggers reviewer escalation"
    elif max_sev == Severity.CRITICAL and len(specific_types) >= 2:
        escalate = True
        escalate_reason = "Multiple critical regressions require reviewer escalation"

    if escalate:
        reasons.append("critical_escalation")
        if has_privacy:
            reasons.append("privacy_check_failed")
        if has_verification:
            reasons.append("verification_check_failed")
        if has_overbroad:
            reasons.append(f"scope_drift_{drift}_roles")
        if has_dup:
            reasons.append("duplicate_scope_overlap")
        if needs_canary:
            reasons.append("canary_invalid")
        return Decision.REVIEWER_ESCALATION, reasons, escalate_reason

    candidates: List[Tuple[Decision, str]] = []

    if has_privacy:
        candidates.append((Decision.ROLLBACK_PRIVACY_REGRESSION, "Privacy regression detected via failed privacy check"))
        reasons.append("privacy_check_failed")

    if has_verification:
        candidates.append((Decision.ROLLBACK_VERIFICATION_REGRESSION, "Verification regression detected via failed verification check"))
        reasons.append("verification_check_failed")

    if has_overbroad:
        candidates.append((Decision.ROLLBACK_OVERBROAD_OUTPUT, f"Patch affected {drift} role(s) beyond declared scope"))
        reasons.append(f"scope_drift_{drift}_roles")

    if has_dup:
        candidates.append((Decision.ROLLBACK_DUPLICATE_SCOPE, "Duplicate scope detected in rollout window"))
        reasons.append("duplicate_scope_overlap")

    if needs_canary:
        candidates.append((Decision.REQUEST_NEW_CANARY, "Canary validation failed; new canary required"))
        reasons.append("canary_invalid")

    if max_sev in (Severity.LOW, Severity.MEDIUM):
        candidates.append((Decision.MONITOR_PATCH, f"Elevated monitoring for {max_sev.value} severity flags"))
        reasons.append(f"monitor_{max_sev.value}_severity")

    if not candidates and max_sev in (Severity.HIGH, Severity.CRITICAL):
        candidates.append((Decision.REVIEWER_ESCALATION,
            f"Unrecognized {max_sev.value} severity flag with no specific rollback match"))
        reasons.append(f"unrecognized_{max_sev.value}_flag_escalation")

    if not candidates:
        candidates.append((Decision.KEEP_PATCH, "No regression flags; all checks pass"))
        reasons.append("all_checks_pass")

    best = min(candidates, key=lambda c: PRECEDENCE_RANK[c[0]])
    return best[0], reasons, best[1]


def reduce_receipts(fixtures: List[Dict[str, Any]]) -> List[RoleDecision]:
    decisions: List[RoleDecision] = []
    for fx in fixtures:
        receipt = _parse_receipt(fx["receipt"])
        decision, triggered, reason = _evaluate_single(receipt)
        drift = _scope_drift_count(receipt)
        max_sev = _max_severity(receipt.regression_flags)
        decisions.append(RoleDecision(
            case_id=receipt.case_id,
            role_id=receipt.role_id,
            patch_id=receipt.patch_id,
            decision=decision.value,
            severity=max_sev.value,
            reviewer_safe_reason=reason,
            triggered_flags=triggered,
            scope_drift_count=drift,
        ))
    return decisions


def print_console_table(
    decisions: List[RoleDecision],
    fixtures: List[Dict[str, Any]],
) -> None:
    sep = "=" * 120
    thin = "-" * 120

    print(sep)
    print(f"  ROLE PATCH ROLLOUT REGRESSION ROUTER  —  v{REDUCER_VERSION}")
    print(f"  Window: {DEFAULT_WINDOW}   |   Fixtures: {len(fixtures)}   |   Decisions: {len(decisions)}")
    print(sep)
    print()

    print(f"  {'#':>2s}  "
          f"{'CASE':<12s}  "
          f"{'ROLE':<20s}  "
          f"{'PATCH':<14s}  "
          f"{'DECISION':<32s}  "
          f"{'SEV':<9s}  "
          f"{'DRIFT'}")
    print(thin)

    for i, d in enumerate(decisions, 1):
        print(f"  {i:>2d}  "
              f"{d.case_id:<12s}  "
              f"{d.role_id:<20s}  "
              f"{d.patch_id:<14s}  "
              f"{d.decision:<32s}  "
              f"{d.severity:<9s}  "
              f"{d.scope_drift_count}")

    print(thin)
    print()

    print(f"  DECISION BREAKDOWN")
    print(thin)
    counts: Dict[str, int] = {}
    for d in decisions:
        counts[d.decision] = counts.get(d.decision, 0) + 1
    for dec_name in sorted(counts.keys()):
        marker = "  " if dec_name == Decision.KEEP_PATCH.value else "**"
        print(f"  {marker} {dec_name:<36s} : {counts[dec_name]}")
    print()

    print(f"  TRIGGER DETAIL")
    print(thin)
    for d in decisions:
        flags_str = ", ".join(d.triggered_flags)
        print(f"  {d.case_id} {d.role_id:<20s}  ->  {d.reviewer_safe_reason}")
        print(f"    triggers: [{flags_str}]")
    print()
    print(sep)


def run_assertions(
    decisions: List[RoleDecision],
    fixtures: List[Dict[str, Any]],
) -> bool:
    all_pass = True
    checked = 0

    for fx, dec in zip(fixtures, decisions):
        fid = fx["fixture_id"]
        expected = fx["expected_decision"]
        checked += 1
        if dec.decision != expected.value:
            print(f"  FAIL {fid}: expected={expected.value} got={dec.decision}")
            all_pass = False

    checked += 1
    if len(decisions) != len(FIXTURES):
        print(f"  FAIL decision count: expected {len(FIXTURES)} got={len(decisions)}")
        all_pass = False

    checked += 1
    distinct_decisions = set(d.decision for d in decisions)
    expected_distinct = {
        "keep_patch", "monitor_patch", "rollback_overbroad_output",
        "rollback_verification_regression", "rollback_privacy_regression",
        "rollback_duplicate_scope", "request_new_canary", "reviewer_escalation",
    }
    if distinct_decisions != expected_distinct:
        missing = expected_distinct - distinct_decisions
        extra = distinct_decisions - expected_distinct
        print(f"  FAIL decision coverage: missing={missing} extra={extra}")
        all_pass = False

    checked += 1
    escalation_cases = [d for d in decisions if d.decision == "reviewer_escalation"]
    for esc in escalation_cases:
        if esc.severity not in ("critical", "high"):
            print(f"  FAIL {esc.case_id}: reviewer_escalation with unexpected severity={esc.severity}")
            all_pass = False

    checked += 1
    privacy_cases = [d for d in decisions if d.decision == "rollback_privacy_regression"]
    for pc in privacy_cases:
        if "privacy_check_failed" not in pc.triggered_flags:
            print(f"  FAIL {pc.case_id}: privacy rollback missing privacy trigger flag")
            all_pass = False

    checked += 1
    overbroad_cases = [d for d in decisions if d.decision == "rollback_overbroad_output"]
    for oc in overbroad_cases:
        if oc.scope_drift_count == 0:
            print(f"  FAIL {oc.case_id}: overbroad rollback with zero scope drift")
            all_pass = False

    checked += 1
    keep_cases = [d for d in decisions if d.decision == "keep_patch"]
    for kc in keep_cases:
        if kc.triggered_flags != ["all_checks_pass"]:
            print(f"  FAIL {kc.case_id}: keep_patch has unexpected triggers={kc.triggered_flags}")
            all_pass = False

    checked += 1
    unrecognized_cases = [d for d in decisions if any("unrecognized_" in t for t in d.triggered_flags)]
    for uc in unrecognized_cases:
        if uc.decision != "reviewer_escalation":
            print(f"  FAIL {uc.case_id}: unrecognized flag escalation got={uc.decision}")
            all_pass = False
    if len(unrecognized_cases) != 2:
        print(f"  FAIL unrecognized flag cases: expected 2 got={len(unrecognized_cases)}")
        all_pass = False

    status = "PASS" if all_pass else "FAIL"
    print(f"\n  Embedded assertions: {checked} checked — {status}\n")
    return all_pass


def main() -> None:
    decisions = reduce_receipts(FIXTURES)

    print_console_table(decisions, FIXTURES)
    all_pass = run_assertions(decisions, FIXTURES)

    checksum_input = json.dumps(
        [{"case_id": d.case_id, "decision": d.decision} for d in decisions],
        sort_keys=True,
    )
    decision_checksum = hashlib.sha256(checksum_input.encode()).hexdigest()[:16]

    output = {
        "reducer": "role_patch_rollout_regression_router",
        "version": REDUCER_VERSION,
        "window": DEFAULT_WINDOW,
        "total_decisions": len(decisions),
        "decision_checksum": decision_checksum,
        "decisions": [asdict(d) for d in decisions],
    }

    print("DETERMINISTIC JSON OUTPUT:")
    print(json.dumps(output, indent=2))

    if not all_pass:
        raise SystemExit(1)

    print("\n  All checks passed.")


if __name__ == "__main__":
    main()
