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

import os

import casbin
from casbin import Decision, DecisionEffect


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


ALLOW_OVERRIDE_MODEL = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act, audit, mask_fields, channel
[policy_effect]
e = some(where (p_eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
[obligation_definition]
o = audit = union, mask_fields = intersection, channel = consensus
"""

DENY_OVERRIDE_MODEL = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act, eft, audit
[policy_effect]
e = !some(where (p_eft == deny))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
[obligation_definition]
o = audit = union
"""

PRIORITY_MODEL = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act, eft, mask_fields
[policy_effect]
e = priority(p_eft) || deny
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
[obligation_definition]
o = mask_fields = union
"""


def get_enforcer(model_text):
    model = casbin.Model()
    model.load_model_from_text(model_text)
    return casbin.Enforcer(model)


class TestDecision:
    def test_enforce_still_returns_plain_bool(self):
        e = get_enforcer(ALLOW_OVERRIDE_MODEL)
        e.add_policy("alice", "data1", "read", "login", "id_card", "secure")

        assert e.enforce("alice", "data1", "read") is True
        assert e.enforce("alice", "data2", "read") is False
        result, explain = e.enforce_ex("alice", "data1", "read")
        assert result is True
        assert explain == ["alice", "data1", "read", "login", "id_card", "secure"]

    def test_allow_and_deny_coexist_under_deny_override(self):
        # allow-override model without eft column: deny can't be expressed, so
        # coexistence is exercised with the deny-override effect model.
        e = get_enforcer(DENY_OVERRIDE_MODEL)
        e.add_policy("alice", "data1", "read", "allow", "allow-audit")
        e.add_policy("alice", "data1", "read", "deny", "deny-audit")

        decision = e.decide("alice", "data1", "read")

        assert isinstance(decision, Decision)
        assert decision.effect == DecisionEffect.DENY
        assert decision.denied
        assert decision.executable
        # only deny rules are eligible; the allow rule's column is not picked
        assert decision.obligations == {"audit": ["deny-audit"]}
        assert decision.explain_rules == [
            ["alice", "data1", "read", "deny", "deny-audit"]
        ]
        # enforce keeps its plain boolean semantics
        assert e.enforce("alice", "data1", "read") is False

    def test_deny_override_without_deny_uses_allows(self):
        e = get_enforcer(DENY_OVERRIDE_MODEL)
        e.add_policy("alice", "data1", "read", "allow", "allow-audit")
        e.add_policy("alice", "data1", "read", "allow", "other-audit")

        decision = e.decide("alice", "data1", "read")

        assert decision.allowed
        assert decision.obligations == {"audit": ["allow-audit", "other-audit"]}

    def test_priority_masks_lower_priority_rules(self):
        e = get_enforcer(PRIORITY_MODEL)
        e.add_policy("alice", "data1", "read", "deny", "ssn")
        e.add_policy("alice", "data1", "read", "allow", "phone")

        decision = e.decide("alice", "data1", "read")

        assert decision.denied
        # only the first (deciding) matched rule contributes
        assert decision.obligations == {"mask_fields": ["ssn"]}
        assert decision.explain_rules == [
            ["alice", "data1", "read", "deny", "ssn"]
        ]

    def test_priority_first_allow_masks_later_allow(self):
        e = get_enforcer(PRIORITY_MODEL)
        e.add_policy("alice", "data1", "read", "allow", "ssn")
        e.add_policy("alice", "data1", "read", "allow", "phone")

        decision = e.decide("alice", "data1", "read")

        assert decision.allowed
        assert decision.obligations == {"mask_fields": ["ssn"]}

    def test_mask_fields_merged_with_union_and_intersection(self):
        e = get_enforcer(ALLOW_OVERRIDE_MODEL)
        e.add_policy("alice", "data1", "read", "login", "id_card", "secure")
        e.add_policy("alice", "data1", "read", "read", "id_card|phone", "secure")

        decision = e.decide("alice", "data1", "read")

        assert decision.allowed
        assert decision.executable
        assert decision.obligations["audit"] == ["login", "read"]
        assert decision.obligations["mask_fields"] == ["id_card"]
        assert decision.obligations["channel"] == ["secure"]
        # both matched allow rules are eligible
        assert len(decision.explain_rules) == 2

    def test_single_value_consensus_conflict_is_indeterminate(self):
        e = get_enforcer(ALLOW_OVERRIDE_MODEL)
        e.add_policy("alice", "data1", "read", "login", "id_card", "secure")
        e.add_policy("alice", "data1", "read", "read", "id_card", "insecure")

        decision = e.decide("alice", "data1", "read")

        assert decision.effect == DecisionEffect.INDETERMINATE
        assert not decision.allowed
        assert not decision.denied
        assert not decision.executable
        assert len(decision.conflicts) == 1
        conflict = decision.conflicts[0]
        assert conflict.name == "channel"
        assert conflict.operator == "consensus"
        assert conflict.values == ["insecure", "secure"]
        # the non-conflicting obligations are still composed and returned
        assert decision.obligations["audit"] == ["login", "read"]
        # callers cannot misread the result as an ordinary boolean allow
        try:
            bool(decision)
        except TypeError:
            pass
        else:
            raise AssertionError("conflicting Decision must not be truthy")
        # enforce itself is unaffected and still returns True
        assert e.enforce("alice", "data1", "read") is True

    def test_consensus_requires_single_value_per_rule(self):
        e = get_enforcer(ALLOW_OVERRIDE_MODEL)
        # one rule demands two channels at once: that can't be a single value
        e.add_policy("alice", "data1", "read", "login", "id_card", "secure|backup")

        decision = e.decide("alice", "data1", "read")

        assert not decision.executable
        assert decision.conflicts[0].name == "channel"

    def test_no_matching_rule_denies_without_obligations(self):
        e = get_enforcer(ALLOW_OVERRIDE_MODEL)
        decision = e.decide("nobody", "data1", "read")

        assert decision.denied
        assert decision.obligations == {
            "audit": [],
            "mask_fields": [],
            "channel": [],
        }
        assert decision.conflicts == []
        assert decision.explain_rules == []

    def test_example_model_and_policy(self):
        e = casbin.Enforcer(
            get_examples("obligation_model.conf"),
            get_examples("obligation_policy.csv"),
        )

        # two agreeing allow rules: union + intersection + consensus all fine
        decision = e.decide("alice", "data1", "read")
        assert decision.allowed
        assert decision.obligations["audit"] == ["login_event", "read_event"]
        assert decision.obligations["mask_fields"] == ["id_card"]
        assert decision.obligations["channel"] == ["secure_channel"]

        # allow + deny coexist: deny wins, only the deny rule contributes
        decision = e.decide("carol", "data1", "read")
        assert decision.denied
        assert decision.obligations["audit"] == ["breach_event"]

    def test_obligations_with_multiple_policy_definitions(self):
        model = casbin.Model()
        model.load_model_from_text(
            """
[request_definition]
r = sub, obj, act
r2 = sub, obj, act
[policy_definition]
p = sub, obj, act
p2 = sub, obj, act, audit
[policy_effect]
e = some(where (p_eft == allow))
e2 = some(where (p2_eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
m2 = r2.sub == p2.sub && r2.obj == p2.obj && r2.act == p2.act
[obligation_definition]
o = audit = union
"""
        )
        e = casbin.Enforcer(model)
        e.add_named_policy("p2", ["alice", "data1", "read", "a1"])
        e.add_named_policy("p2", ["alice", "data1", "read", "a2"])

        decision = e.decide(e.new_enforce_context("2"), "alice", "data1", "read")

        assert decision.allowed
        assert decision.obligations == {"audit": ["a1", "a2"]}


class TestObligationComposition:
    def test_union_intersection_consensus(self):
        from casbin import (
            merge_obligations,
            parse_obligation_definition,
        )

        definition = parse_obligation_definition(
            "audit = union, mask = intersection, channel = consensus"
        )
        assert list(definition.items()) == [
            ("audit", "union"),
            ("mask", "intersection"),
            ("channel", "consensus"),
        ]

        obligations, conflicts = merge_obligations(
            definition,
            [
                {"audit": ["a"], "mask": ["x", "y"], "channel": ["s"]},
                {"audit": ["b"], "mask": ["y", "z"], "channel": ["s"]},
            ],
        )
        assert obligations == {
            "audit": ["a", "b"],
            "mask": ["y"],
            "channel": ["s"],
        }
        assert conflicts == []

    def test_invalid_operator_rejected(self):
        from casbin import parse_obligation_definition

        try:
            parse_obligation_definition("audit = first_match")
        except RuntimeError:
            pass
        else:
            raise AssertionError("unknown operator must be rejected")
