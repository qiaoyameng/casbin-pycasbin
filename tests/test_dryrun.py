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
from unittest import TestCase

import casbin
from casbin.dryrun import (
    ImpactAnalysisError,
    add_grouping_policy,
    add_policy,
    analyze_policy_impact,
    remove_grouping_policy,
    remove_policy,
)


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


class TestDryRunImpactAnalysis(TestCase):
    def get_enforcer(self, model, policy):
        return casbin.Enforcer(get_examples(model), get_examples(policy))

    def test_added_and_revoked_allows(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        report = analyze_policy_impact(
            e,
            edits=[
                remove_policy(["alice", "data1", "read"]),
                add_policy(["bob", "data2", "read"]),
            ],
            users=["alice", "bob"],
            resources=["data1", "data2"],
            actions=["read", "write"],
        )

        revoked = {i.request for i in report.revoked_allows}
        added = {i.request for i in report.added_allows}
        self.assertEqual(revoked, {("alice", "data1", "read")})
        self.assertEqual(added, {("bob", "data2", "read")})
        self.assertEqual(len(report.impacts), 8)
        self.assertEqual(len(report.unchanged), 6)

        # evidence for review: before/after policy snapshots and matched rules
        self.assertIn(["alice", "data1", "read"], report.before_policies["p"]["p"])
        self.assertNotIn(["alice", "data1", "read"], report.after_policies["p"]["p"])
        impact = next(i for i in report.impacts if i.request == ("alice", "data1", "read"))
        self.assertEqual(impact.before_explain, ["alice", "data1", "read"])
        self.assertEqual(impact.after_explain, [])

        # the live enforcer is untouched
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "read"))

    def test_alternative_paths_no_false_revocation(self):
        # alice has two independent authorization paths for (data1, read):
        # a direct allow rule and the inherited data2_admin role rule.
        # Deleting the direct rule must NOT be reported as a revocation.
        e = self.get_enforcer("rbac_model.conf", "rbac_with_hierarchy_policy.csv")
        self.assertTrue(e.enforce("alice", "data1", "read"))

        report = analyze_policy_impact(
            e,
            edits=[remove_policy(["alice", "data1", "read"])],
            users=["alice"],
            resources=["data1"],
            actions=["read"],
        )

        self.assertEqual(report.revoked_allows, [])
        self.assertEqual(report.added_allows, [])
        self.assertEqual(len(report.unchanged), 1)
        impact = report.unchanged[0]
        self.assertEqual(impact.change, "unchanged_allow")
        self.assertTrue(impact.before)
        self.assertTrue(impact.after)
        # evidence shows the remaining path via the inherited role
        self.assertEqual(impact.before_explain, ["alice", "data1", "read"])
        self.assertEqual(impact.after_explain, ["data1_admin", "data1", "read"])
        # g-relation evidence is kept for review
        self.assertIn("data1_admin", report.roles_before["alice"])
        self.assertIn("data1_admin", report.roles_after["alice"])

    def test_grouping_edit_indirect_impact(self):
        e = self.get_enforcer("rbac_model.conf", "rbac_policy.csv")
        report = analyze_policy_impact(
            e,
            edits=[remove_grouping_policy(["alice", "data2_admin"])],
            users=["alice"],
            resources=["data2"],
            actions=["read", "write"],
        )
        revoked = {i.request for i in report.revoked_allows}
        self.assertEqual(revoked, {("alice", "data2", "read"), ("alice", "data2", "write")})
        self.assertEqual(report.roles_after["alice"], [])

    def test_no_adapter_writes_and_enforcer_untouched(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        before_p = [list(r) for r in e.model["p"]["p"].policy]
        report = analyze_policy_impact(
            e,
            edits=[add_policy(["eve", "data3", "read"])],
            users=["eve"],
            resources=["data3"],
            actions=["read"],
        )
        self.assertEqual(len(report.added_allows), 1)
        self.assertEqual([list(r) for r in e.model["p"]["p"].policy], before_p)
        self.assertFalse(e.enforce("eve", "data3", "read"))

    def test_noop_edit_recorded_as_limitation(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        report = analyze_policy_impact(
            e,
            edits=[remove_policy(["nobody", "data9", "read"])],
            users=["alice"],
            resources=["data1"],
            actions=["read"],
        )
        self.assertTrue(any("no effect" in lim for lim in report.limitations))
        self.assertEqual(report.revoked_allows, [])

    def test_unstable_custom_function_reported(self):
        state = {"flip": False}

        def unstable_func(*args):
            state["flip"] = not state["flip"]
            return state["flip"]

        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && unstableFunc(r.obj, p.obj) && r.act == p.act
"""
        m = casbin.model.Model()
        m.load_model_from_text(model_text)
        m.add_policy("p", "p", ["alice", "data1", "read"])
        e2 = casbin.Enforcer(m)
        report2 = analyze_policy_impact(
            e2,
            edits=[],
            users=["alice"],
            resources=["data1"],
            actions=["read"],
            functions={"unstableFunc": unstable_func},
        )
        self.assertEqual(len(report2.indeterminate), 1)
        self.assertTrue(any("unstable" in lim for lim in report2.limitations))
        self.assertTrue(any("indeterminate" in lim for lim in report2.limitations))

    def test_evaluation_error_reported_as_limitation(self):
        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && boom(r.obj) && r.act == p.act
"""
        m = casbin.model.Model()
        m.load_model_from_text(model_text)
        m.add_policy("p", "p", ["alice", "data1", "read"])
        e = casbin.Enforcer(m)

        def boom(_):
            raise ValueError("broken custom function")

        report = analyze_policy_impact(
            e,
            edits=[],
            users=["alice"],
            resources=["data1"],
            actions=["read"],
            functions={"boom": boom},
        )
        self.assertEqual(len(report.indeterminate), 1)
        self.assertIn("broken custom function", report.impacts[0].note)
        self.assertTrue(any("could not be evaluated" in lim for lim in report.limitations))

    def test_scope_note_and_text_report(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        report = analyze_policy_impact(
            e,
            edits=[remove_policy(["alice", "data1", "read"])],
            users=["alice", "bob"],
            resources=["data1"],
            actions=["read"],
        )
        note = report.scope_note()
        self.assertIn("2 users x 1 resources x 1 actions = 2 requests", note)
        self.assertIn("outside this domain", note)
        text = report.to_text()
        self.assertIn("Scope:", text)
        self.assertIn("Revoked allows:", text)
        self.assertIn("alice", text)

    def test_non_3_part_request_rejected(self):
        e = self.get_enforcer("rbac_with_domains_model.conf", "rbac_with_domains_policy.csv")
        with self.assertRaises(ImpactAnalysisError):
            analyze_policy_impact(
                e,
                edits=[],
                users=["alice"],
                resources=["data1"],
                actions=["read"],
            )
