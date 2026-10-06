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

"""Structured decision types and obligation composition.

An obligation is a data value attached to a policy rule (an extra column of
the policy definition), for example ``audit`` ("record an audit event") or
``mask`` ("mask the id card field").  When several rules contribute to one
decision their obligation values are combined with one of three operators:

* ``union``        -- set union of every contributing value;
* ``intersection`` -- only values required by every contributing rule;
* ``consensus``    -- every contributing rule must require the exact same
                      single value, otherwise an explicit conflict is reported.

Conflicts never raise and never silently degrade into a normal allow: the
returned :class:`Decision` is marked ``indeterminate`` and carries the list
of :class:`ObligationConflict`, so callers cannot mistake it for an ordinary
permission grant.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple

OBLIGATION_UNION = "union"
OBLIGATION_INTERSECTION = "intersection"
OBLIGATION_CONSENSUS = "consensus"

_VALID_OPERATORS = (OBLIGATION_UNION, OBLIGATION_INTERSECTION, OBLIGATION_CONSENSUS)

# Values inside one policy cell are separated with "|", e.g. "id_card|phone".
VALUE_SEPARATOR = "|"


class DecisionEffect(Enum):
    """Outcome of a structured decision."""

    ALLOW = "allow"
    DENY = "deny"
    # The request could not be decided safely: policy obligations could not be
    # combined into an executable set. Must never be treated as a plain allow.
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class ObligationConflict:
    """Describes why one obligation could not be composed."""

    name: str
    operator: str
    # The distinct, disagreeing values required by the contributing rules.
    values: List[str]


@dataclass
class Decision:
    """Structured authorization result.

    ``effect`` is one of :class:`DecisionEffect`; ``obligations`` maps each
    declared obligation name to the composed values; ``conflicts`` lists the
    obligations that could not be composed; ``explain_rules`` holds the policy
    rules that were eligible to contribute.
    """

    effect: DecisionEffect
    obligations: Dict[str, List[str]] = field(default_factory=dict)
    conflicts: List[ObligationConflict] = field(default_factory=list)
    explain_rules: List[List[str]] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.effect == DecisionEffect.ALLOW and not self.conflicts

    @property
    def denied(self) -> bool:
        return self.effect == DecisionEffect.DENY and not self.conflicts

    @property
    def executable(self) -> bool:
        """True only when there is no obligation conflict.

        An indeterminate decision (or a raw allow/deny that carries a
        conflict) must not be executed as an ordinary authorization result.
        """
        return self.effect != DecisionEffect.INDETERMINATE and not self.conflicts

    def __bool__(self):
        # Refuse to be silently used where the caller expected the boolean
        # result of Enforcer.enforce(): forcing callers to inspect
        # `allowed` / `executable` is what makes an unexecutable decision
        # unmistakeable.
        raise TypeError(
            "Decision is not a boolean; use decision.allowed, decision.denied "
            "or decision.executable (and inspect decision.conflicts)"
        )


def parse_obligation_definition(value: str) -> "OrderedDict[str, str]":
    """Parses an ``obligation_definition`` assertion value.

    The syntax mirrors the other model sections, for example::

        o = audit = union, mask_fields = intersection, channel = consensus

    Returns an ordered mapping ``obligation name -> combine operator``.
    """
    definition: "OrderedDict[str, str]" = OrderedDict()
    if not value:
        return definition

    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        if "=" not in item:
            raise RuntimeError(
                f"invalid obligation definition '{item}': expected '<name> = <operator>'"
            )
        name, operator = item.split("=", 1)
        name = name.strip()
        operator = operator.strip()
        if not name:
            raise RuntimeError(f"invalid obligation definition '{item}': empty name")
        if operator not in _VALID_OPERATORS:
            raise RuntimeError(
                f"invalid obligation operator '{operator}' for '{name}', "
                f"expected one of {', '.join(_VALID_OPERATORS)}"
            )
        definition[name] = operator
    return definition


def split_obligation_value(raw: str) -> List[str]:
    """Splits one policy cell into its individual obligation values."""
    if raw is None:
        return []
    return [piece.strip() for piece in str(raw).split(VALUE_SEPARATOR) if piece.strip()]


def merge_obligations(
    definition: "OrderedDict[str, str]",
    contributions: List[Dict[str, List[str]]],
) -> Tuple[Dict[str, List[str]], List[ObligationConflict]]:
    """Combines the per-rule obligation contributions.

    ``contributions`` is an ordered list with one mapping per eligible rule,
    already restricted to the rules that may contribute under the active
    effect model. Returns the composed obligations together with the
    conflicts; a conflict means the decision is unexecutable.
    """
    obligations: Dict[str, List[str]] = OrderedDict()
    conflicts: List[ObligationConflict] = []

    for name, operator in definition.items():
        # Only rules that actually carry a value for this obligation take part
        # in the composition: a rule whose cell is empty simply does not
        # contribute, rather than contributing an empty set.
        rule_values = [contrib[name] for contrib in contributions if contrib.get(name)]

        if operator == OBLIGATION_UNION:
            obligations[name] = sorted({value for values in rule_values for value in values})
            continue

        if operator == OBLIGATION_INTERSECTION:
            value_sets = [set(values) for values in rule_values]
            merged_set = set.intersection(*value_sets) if value_sets else set()
            obligations[name] = sorted(merged_set)
            continue

        # consensus: every contributing rule must demand exactly one and the
        # same value.
        distinct = [tuple(sorted(set(values))) for values in rule_values]
        if not distinct:
            obligations[name] = []
        else:
            unique = set(distinct)
            if len(unique) == 1 and len(next(iter(unique))) == 1:
                obligations[name] = [next(iter(unique))[0]]
            else:
                disagreeing = sorted({value for values in distinct for value in values})
                conflicts.append(
                    ObligationConflict(name=name, operator=operator, values=disagreeing)
                )

    return obligations, conflicts
