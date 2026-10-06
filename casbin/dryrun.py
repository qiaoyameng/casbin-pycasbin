# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Dry-run impact analysis for proposed policy edits.

This module answers the question "who gains or loses which permission if
these policy edits are applied?" without touching the live enforcer or any
adapter. It builds two independent in-memory models (current and candidate),
evaluates an explicitly provided finite request domain against both, and
reports added allows, revoked allows and unchanged requests.

Decisions are derived from enforcement results, never from raw rule diffs:
deleting an ``allow`` rule is NOT equated with revoking the permission,
because other rules or ``g`` role inheritance may still grant it.

Accuracy is guaranteed only inside the explicitly given request domain.
Nothing is inferred about users, resources or actions outside that domain.
"""

import copy
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .enforcer import Enforcer

__all__ = [
    "PolicyEdit",
    "RequestImpact",
    "ImpactReport",
    "ImpactAnalysisError",
    "analyze_policy_impact",
    "add_policy",
    "remove_policy",
    "add_grouping_policy",
    "remove_grouping_policy",
]

CHANGE_ADDED_ALLOW = "added_allow"
CHANGE_REVOKED_ALLOW = "revoked_allow"
CHANGE_UNCHANGED_ALLOW = "unchanged_allow"
CHANGE_UNCHANGED_DENY = "unchanged_deny"
CHANGE_INDETERMINATE = "indeterminate"


class ImpactAnalysisError(RuntimeError):
    """Raised when the impact analysis cannot be performed at all."""


@dataclass(frozen=True)
class PolicyEdit:
    """A single proposed policy edit, applied only to the candidate model."""

    op: str  # "add" or "remove"
    sec: str  # "p" or "g"
    ptype: str  # e.g. "p", "p2", "g", "g2"
    rule: Tuple[str, ...]

    def __post_init__(self):
        if self.op not in ("add", "remove"):
            raise ValueError(f"invalid edit op: {self.op!r} (expected 'add' or 'remove')")
        if self.sec not in ("p", "g"):
            raise ValueError(f"invalid edit sec: {self.sec!r} (expected 'p' or 'g')")
        object.__setattr__(self, "rule", tuple(str(v) for v in self.rule))

    def describe(self) -> str:
        return f"{self.op} {self.sec}/{self.ptype} {list(self.rule)}"


def add_policy(rule: Sequence[str], ptype: str = "p") -> PolicyEdit:
    return PolicyEdit("add", "p", ptype, tuple(rule))


def remove_policy(rule: Sequence[str], ptype: str = "p") -> PolicyEdit:
    return PolicyEdit("remove", "p", ptype, tuple(rule))


def add_grouping_policy(rule: Sequence[str], ptype: str = "g") -> PolicyEdit:
    return PolicyEdit("add", "g", ptype, tuple(rule))


def remove_grouping_policy(rule: Sequence[str], ptype: str = "g") -> PolicyEdit:
    return PolicyEdit("remove", "g", ptype, tuple(rule))


@dataclass
class RequestImpact:
    """The before/after outcome for one request, with reviewable evidence."""

    request: Tuple[str, str, str]
    before: Optional[bool]
    after: Optional[bool]
    change: str
    before_explain: List[str] = field(default_factory=list)
    after_explain: List[str] = field(default_factory=list)
    note: Optional[str] = None


@dataclass
class ImpactReport:
    """Result of a dry-run impact analysis.

    The report is exact only for ``users x resources x actions`` as recorded
    here; it must not be read as covering any request outside that domain.
    """

    users: Tuple[str, ...]
    resources: Tuple[str, ...]
    actions: Tuple[str, ...]
    edits: List[PolicyEdit]
    before_policies: Dict[str, Dict[str, List[List[str]]]]
    after_policies: Dict[str, Dict[str, List[List[str]]]]
    roles_before: Dict[str, List[str]]
    roles_after: Dict[str, List[str]]
    impacts: List[RequestImpact]
    limitations: List[str]

    @property
    def added_allows(self) -> List[RequestImpact]:
        return [i for i in self.impacts if i.change == CHANGE_ADDED_ALLOW]

    @property
    def revoked_allows(self) -> List[RequestImpact]:
        return [i for i in self.impacts if i.change == CHANGE_REVOKED_ALLOW]

    @property
    def unchanged(self) -> List[RequestImpact]:
        return [i for i in self.impacts if i.change in (CHANGE_UNCHANGED_ALLOW, CHANGE_UNCHANGED_DENY)]

    @property
    def indeterminate(self) -> List[RequestImpact]:
        return [i for i in self.impacts if i.change == CHANGE_INDETERMINATE]

    def scope_note(self) -> str:
        total = len(self.users) * len(self.resources) * len(self.actions)
        return (
            "Scope: this analysis is exact only for the explicitly provided "
            f"request domain ({len(self.users)} users x {len(self.resources)} "
            f"resources x {len(self.actions)} actions = {total} requests). "
            "It makes no claim about any user, resource, action or business "
            "data outside this domain."
        )

    def to_text(self) -> str:
        lines = [self.scope_note(), ""]
        lines.append("Proposed edits (applied to the candidate model only):")
        for edit in self.edits:
            lines.append(f"  - {edit.describe()}")
        lines.append("")
        lines.append(
            f"Summary: {len(self.added_allows)} added allow(s), "
            f"{len(self.revoked_allows)} revoked allow(s), "
            f"{len(self.unchanged)} unchanged, "
            f"{len(self.indeterminate)} indeterminate."
        )

        def render(title, items):
            lines.append("")
            lines.append(title)
            for impact in items:
                lines.append(
                    f"  - {list(impact.request)}: {impact.before} -> {impact.after}"
                )
                lines.append(f"      before evidence: {impact.before_explain or '[]'}")
                lines.append(f"      after evidence:  {impact.after_explain or '[]'}")
                if impact.note:
                    lines.append(f"      note: {impact.note}")

        render("Added allows:", self.added_allows)
        render("Revoked allows:", self.revoked_allows)
        if self.limitations:
            lines.append("")
            lines.append("Limitations:")
            for limitation in self.limitations:
                lines.append(f"  - {limitation}")
        return "\n".join(lines)


def _snapshot_policies(model) -> Dict[str, Dict[str, List[List[str]]]]:
    snapshot: Dict[str, Dict[str, List[List[str]]]] = {}
    for sec in ("p", "g"):
        if sec not in model.keys():
            continue
        snapshot[sec] = {}
        for ptype, ast in model[sec].items():
            snapshot[sec][ptype] = [list(rule) for rule in ast.policy]
    return snapshot


def _apply_edits(model, edits: Sequence[PolicyEdit], limitations: List[str]) -> None:
    for edit in edits:
        if edit.sec not in model.keys() or edit.ptype not in model[edit.sec].keys():
            limitations.append(
                f"edit not applied (no such assertion): {edit.describe()}"
            )
            continue
        if edit.op == "add":
            applied = model.add_policy(edit.sec, edit.ptype, list(edit.rule))
        else:
            applied = model.remove_policy(edit.sec, edit.ptype, list(edit.rule))
        if not applied:
            reason = "rule already exists" if edit.op == "add" else "rule not found"
            limitations.append(f"edit had no effect ({reason}): {edit.describe()}")


def _build_analysis_enforcer(model, functions: Optional[Mapping[str, Callable]]) -> Enforcer:
    enforcer = Enforcer(model)
    enforcer.enable_auto_save(False)
    enforcer.enable_auto_notify_watcher(False)
    if functions:
        for name, fn in functions.items():
            enforcer.add_function(name, fn)
    enforcer.build_role_links()
    return enforcer


def _enforce_stable(enforcer, request, stability_runs: int):
    """Returns (decision, explain, note). decision is None on failure."""
    results = []
    explain: List[str] = []
    for _ in range(max(1, stability_runs)):
        result, explain_rule = enforcer.enforce_ex(*request)
        results.append(bool(result))
        if explain_rule:
            explain = list(explain_rule)
    if len(set(results)) > 1:
        return None, explain, (
            "unstable result across repeated evaluations "
            "(non-deterministic matcher or custom function)"
        )
    return results[0], explain, None


def _classify(before: Optional[bool], after: Optional[bool]) -> str:
    if before is None or after is None:
        return CHANGE_INDETERMINATE
    if before and after:
        return CHANGE_UNCHANGED_ALLOW
    if not before and not after:
        return CHANGE_UNCHANGED_DENY
    if after:
        return CHANGE_ADDED_ALLOW
    return CHANGE_REVOKED_ALLOW


def analyze_policy_impact(
    enforcer,
    edits: Sequence[PolicyEdit],
    users: Sequence[str],
    resources: Sequence[str],
    actions: Sequence[str],
    *,
    functions: Optional[Mapping[str, Callable]] = None,
    stability_runs: int = 2,
) -> ImpactReport:
    """Analyzes the impact of proposed policy edits on a finite request domain.

    ``enforcer`` is only read from: its model is deep-copied twice and the
    copies are evaluated by two independent throwaway enforcers. The live
    enforcer, its adapter and any watcher are never modified or written to.

    ``edits`` are applied to the candidate model only. ``users``,
    ``resources`` and ``actions`` define the exact request domain
    (sub, obj, act); accuracy is guaranteed only within this domain.

    ``functions`` may carry custom matcher functions; they are registered on
    both analysis enforcers. ``stability_runs`` controls how often each
    request is re-evaluated per side to detect non-deterministic custom
    functions; unstable requests are reported as indeterminate.
    """
    limitations: List[str] = []

    if "r" not in enforcer.model.keys() or "r" not in enforcer.model["r"].keys():
        raise ImpactAnalysisError("model has no request definition 'r'")
    r_tokens = enforcer.model["r"]["r"].tokens
    if len(r_tokens) != 3:
        raise ImpactAnalysisError(
            "impact analysis expects a 3-part request (sub, obj, act); "
            f"this model declares {r_tokens}"
        )

    before_policies = _snapshot_policies(enforcer.model)

    before_model = copy.deepcopy(enforcer.model)
    after_model = copy.deepcopy(enforcer.model)
    _apply_edits(after_model, edits, limitations)
    after_policies = _snapshot_policies(after_model)

    try:
        before_enforcer = _build_analysis_enforcer(before_model, functions)
        after_enforcer = _build_analysis_enforcer(after_model, functions)
    except Exception as exc:
        raise ImpactAnalysisError(f"failed to build analysis enforcers: {exc}") from exc

    users = tuple(str(u) for u in users)
    resources = tuple(str(r) for r in resources)
    actions = tuple(str(a) for a in actions)

    roles_before: Dict[str, List[str]] = {}
    roles_after: Dict[str, List[str]] = {}
    if "g" in enforcer.model.keys():
        for user in users:
            try:
                roles_before[user] = sorted(before_enforcer.get_implicit_roles_for_user(user))
                roles_after[user] = sorted(after_enforcer.get_implicit_roles_for_user(user))
            except Exception as exc:
                limitations.append(f"could not resolve implicit roles for {user!r}: {exc}")

    impacts: List[RequestImpact] = []
    unstable_seen = False
    error_seen = False
    for user in users:
        for resource in resources:
            for action in actions:
                request = (user, resource, action)
                notes = []
                try:
                    before, before_explain, note = _enforce_stable(before_enforcer, request, stability_runs)
                except Exception as exc:
                    before, before_explain, note = None, [], f"before evaluation failed: {exc}"
                if note:
                    notes.append(note)
                try:
                    after, after_explain, note = _enforce_stable(after_enforcer, request, stability_runs)
                except Exception as exc:
                    after, after_explain, note = None, [], f"after evaluation failed: {exc}"
                if note:
                    notes.append(note)
                for note in notes:
                    if "unstable" in note:
                        unstable_seen = True
                    if "failed" in note:
                        error_seen = True
                impacts.append(
                    RequestImpact(
                        request=request,
                        before=before,
                        after=after,
                        change=_classify(before, after),
                        before_explain=before_explain,
                        after_explain=after_explain,
                        note="; ".join(notes) if notes else None,
                    )
                )

    if unstable_seen:
        limitations.append(
            "some requests gave inconsistent results across repeated "
            "evaluations (unstable custom function or matcher); they are "
            "reported as indeterminate"
        )
    if error_seen:
        limitations.append(
            "some requests could not be evaluated (see per-request notes); "
            "they are reported as indeterminate"
        )

    return ImpactReport(
        users=users,
        resources=resources,
        actions=actions,
        edits=list(edits),
        before_policies=before_policies,
        after_policies=after_policies,
        roles_before=roles_before,
        roles_after=roles_after,
        impacts=impacts,
        limitations=limitations,
    )
