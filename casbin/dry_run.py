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

"""Dry-run policy impact analysis.

This module evaluates *proposed* policy edits against an explicitly given,
finite request domain, using two independent shadow models (current and
candidate). It reports which requests would become allowed, which would be
revoked, and which are unchanged - including indirect effects through
grouping ("g") relations.

The analysis never mutates the source enforcer and never performs adapter
writes. Results are decision-level: removing an "allow" rule is only
reported as a revocation when the final decision of a request actually
changes (e.g. the subject may still be allowed through another
authorization path).
"""

import copy
from dataclasses import dataclass, field
from itertools import product

from casbin.enforcer import Enforcer
from casbin.model.function import FunctionMap

__all__ = [
    "ADD",
    "REMOVE",
    "PolicyEdit",
    "RequestImpact",
    "ImpactReport",
    "analyze_policy_impact",
]

ADD = "add"
REMOVE = "remove"

_OPS = (ADD, REMOVE)


@dataclass(frozen=True)
class PolicyEdit:
    """A single proposed policy edit.

    op:    "add" or "remove".
    rule:  the policy rule, e.g. ("alice", "data1", "read").
    sec:   "p" for authorization rules, "g" for grouping rules.
    ptype: the policy type, defaults to the value of sec ("p"/"g").
    """

    op: str
    rule: tuple
    sec: str = "p"
    ptype: str = None

    def __post_init__(self):
        if self.op not in _OPS:
            raise ValueError(f"invalid edit op: {self.op!r}, expected one of {_OPS}")
        if self.sec not in ("p", "g"):
            raise ValueError(f"invalid edit sec: {self.sec!r}, expected 'p' or 'g'")
        object.__setattr__(self, "rule", tuple(self.rule))
        if self.ptype is None:
            object.__setattr__(self, "ptype", self.sec)

    @staticmethod
    def add(rule, sec="p", ptype=None):
        return PolicyEdit(ADD, rule, sec, ptype)

    @staticmethod
    def remove(rule, sec="p", ptype=None):
        return PolicyEdit(REMOVE, rule, sec, ptype)


@dataclass
class RequestImpact:
    """The before/after evaluation evidence for a single request."""

    request: tuple
    before: bool
    after: bool
    before_explain: list = field(default_factory=list)
    after_explain: list = field(default_factory=list)


@dataclass
class ImpactReport:
    """Result of a dry-run impact analysis.

    The lists contain the full evidence for every request in the analyzed
    domain, so each classification can be reviewed against the matched
    policy rules before and after the proposed edits.
    """

    edits: list = field(default_factory=list)
    ineffective_edits: list = field(default_factory=list)
    newly_allowed: list = field(default_factory=list)
    revoked: list = field(default_factory=list)
    unchanged_allowed: list = field(default_factory=list)
    unchanged_denied: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    limitations: list = field(default_factory=list)
    scope: str = ""
    total_requests: int = 0
    policy_counts_before: dict = field(default_factory=dict)
    policy_counts_after: dict = field(default_factory=dict)

    @property
    def changed(self):
        return len(self.newly_allowed) + len(self.revoked)

    def summary(self):
        lines = [
            "Dry-run policy impact analysis",
            f"Scope: {self.scope}",
            f"Requests evaluated: {self.total_requests}",
            f"Newly allowed: {len(self.newly_allowed)}",
            f"Revoked: {len(self.revoked)}",
            f"Unchanged (allowed): {len(self.unchanged_allowed)}",
            f"Unchanged (denied): {len(self.unchanged_denied)}",
        ]
        if self.ineffective_edits:
            lines.append(f"Edits with no effect on the policy: {len(self.ineffective_edits)}")
        if self.errors:
            lines.append(f"Evaluation errors: {len(self.errors)}")
        for limitation in self.limitations:
            lines.append(f"Limitation: {limitation}")
        return "\n".join(lines)


def _normalize_edit(edit):
    if isinstance(edit, PolicyEdit):
        return edit
    if isinstance(edit, dict):
        return PolicyEdit(
            edit["op"],
            edit["rule"],
            edit.get("sec", "p"),
            edit.get("ptype"),
        )
    raise ValueError(f"unsupported policy edit: {edit!r}")


def _policy_counts(model):
    counts = {}
    for sec in ("p", "g"):
        if sec in model.model.keys():
            for ptype, ast in model.model[sec].items():
                counts[f"{sec}/{ptype}"] = len(ast.policy)
    return counts


def _shadow_enforcer(source, model):
    """Builds an independent enforcer from a copied model.

    The shadow enforcer has no adapter, so its management API cannot
    perform any persistence writes.
    """
    shadow = Enforcer(model)
    shadow.enable_auto_save(False)
    shadow.enable_auto_notify_watcher(False)

    builtin_names = set(FunctionMap.load_function_map().get_functions().keys())
    for name, fn in source.fm.get_functions().items():
        if name not in builtin_names:
            shadow.add_function(name, fn)

    for ptype, rm in getattr(source, "rm_map", {}).items():
        if ptype in shadow.rm_map:
            for attr in ("matching_func", "domain_matching_func"):
                fn = getattr(rm, attr, None)
                if fn is not None:
                    setattr(shadow.rm_map[ptype], attr, fn)

    shadow.build_role_links()
    return shadow


def analyze_policy_impact(enforcer, edits, users=None, resources=None, actions=None, requests=None):
    """Analyzes the impact of proposed policy edits without applying them.

    enforcer:  the current enforcer, used read-only as the baseline.
    edits:     proposed PolicyEdit items (or dicts with op/rule/sec/ptype).
    users/resources/actions:
               explicit finite sets; the analyzed request domain is their
               cartesian product (sub, obj, act).
    requests:  alternatively, an explicit iterable of request tuples.

    Returns an ImpactReport. The report is only valid for the explicitly
    given finite request domain and says so in its scope and limitations.
    """
    edits = [_normalize_edit(edit) for edit in edits]

    if requests is None:
        if users is None or resources is None or actions is None:
            raise ValueError("either requests or users/resources/actions must be provided")
        users, resources, actions = list(users), list(resources), list(actions)
        requests = list(product(users, resources, actions))
        scope = (
            f"{len(users)} user(s) x {len(resources)} resource(s) x {len(actions)} action(s) "
            f"= {len(requests)} request(s)"
        )
    else:
        requests = [tuple(request) for request in requests]
        scope = f"{len(requests)} explicitly provided request(s)"

    report = ImpactReport(edits=edits, scope=scope, total_requests=len(requests))
    report.limitations.append(
        "results only cover the explicitly given finite request domain "
        f"({scope}); they do not cover users, resources, or actions outside it"
    )
    report.limitations.append(
        "decisions are computed by evaluating both models; removing an allow rule "
        "is reported as a revocation only if a request's final decision changes"
    )
    report.limitations.append(
        "dry-run only: the current enforcer was not modified and no adapter writes were performed"
    )

    source_model = enforcer.get_model()
    report.policy_counts_before = _policy_counts(source_model)

    before_enforcer = _shadow_enforcer(enforcer, copy.deepcopy(source_model))
    after_enforcer = _shadow_enforcer(enforcer, copy.deepcopy(source_model))

    for edit in edits:
        if edit.op == ADD:
            applied = after_enforcer._add_policy(edit.sec, edit.ptype, list(edit.rule))
        else:
            applied = after_enforcer._remove_policy(edit.sec, edit.ptype, list(edit.rule))
        if not applied:
            report.ineffective_edits.append(edit)
            report.limitations.append(f"edit had no effect on the candidate policy: {edit!r}")

    if any(edit.sec == "g" for edit in edits):
        after_enforcer.build_role_links()

    report.policy_counts_after = _policy_counts(after_enforcer.get_model())

    custom_functions = sorted(
        name
        for name in enforcer.fm.get_functions().keys()
        if name not in FunctionMap.load_function_map().get_functions()
    )
    check_stability = bool(custom_functions)
    if check_stability:
        report.limitations.append(
            "model uses custom function(s) "
            + ", ".join(custom_functions)
            + "; they are assumed to be deterministic and side-effect free during evaluation"
        )

    unstable = False
    for request in requests:
        try:
            before, before_explain = before_enforcer.enforce_ex(*request)
            after, after_explain = after_enforcer.enforce_ex(*request)
            if check_stability:
                before_repeat, _ = before_enforcer.enforce_ex(*request)
                after_repeat, _ = after_enforcer.enforce_ex(*request)
                if before_repeat != before or after_repeat != after:
                    unstable = True
        except Exception as exc:
            report.errors.append(f"request {request!r} failed to evaluate: {exc}")
            continue

        impact = RequestImpact(
            request=tuple(request),
            before=before,
            after=after,
            before_explain=list(before_explain),
            after_explain=list(after_explain),
        )
        if before and after:
            report.unchanged_allowed.append(impact)
        elif not before and not after:
            report.unchanged_denied.append(impact)
        elif after:
            report.newly_allowed.append(impact)
        else:
            report.revoked.append(impact)

    if unstable:
        report.limitations.append(
            "custom function evaluation produced inconsistent results across repeated "
            "evaluations; affected requests may be misclassified"
        )
    if report.errors:
        report.limitations.append(
            f"{len(report.errors)} request(s) failed to evaluate; the report is partial"
        )

    return report
