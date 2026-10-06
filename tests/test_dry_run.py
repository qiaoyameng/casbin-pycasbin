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
from casbin.dry_run import PolicyEdit, analyze_policy_impact


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


def get_enforcer():
    return casbin.Enforcer(
        get_examples("rbac_model.conf"),
        get_examples("rbac_policy.csv"),
    )


class FailingWriteAdapter(casbin.persist.Adapter):
    """An adapter that proves the analysis never writes anything."""

    def load_policy(self, model):
        pass

    def save_policy(self, model):
        raise AssertionError("dry-run analysis must not save policies")

    def add_policy(self, sec, ptype, rule):
        raise AssertionError("dry-run analysis must not add policies")

    def remove_policy(self, sec, ptype, rule):
        raise AssertionError("dry-run analysis must not remove policies")

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        raise AssertionError("dry-run analysis must not remove policies")


class TestDryRun(TestCase):
    def test_newly_allowed_and_unchanged(self):
        e = get_enforcer()
        report = analyze_policy_impact(
            e,
            [PolicyEdit.add(("bob", "data1", "read"))],
            users={"alice", "bob"},
            resources={"data1"},
            actions={"read"},
        )

        self.assertEqual(report.total_requests, 2)
        self.assertEqual([i.request for i in report.newly_allowed], [("bob", "data1", "read")])
        self.assertEqual(report.revoked, [])
        self.assertEqual([i.request for i in report.unchanged_allowed], [("alice", "data1", "read")])

        impact = report.newly_allowed[0]
        self.assertFalse(impact.before)
        self.assertTrue(impact.after)
        self.assertEqual(impact.after_explain, ["bob", "data1", "read"])

    def test_remove_one_of_two_alternative_paths_is_not_a_revocation(self):
        # alice can read data2 through two alternative authorization paths:
        # a direct allow rule and the inherited data2_admin role.
        m = casbin.model.Model()
        m.load_model(get_examples("rbac_model.conf"))
        e = casbin.Enforcer(m)
        e.add_policy("alice", "data2", "read")
        e.add_policy("data2_admin", "data2", "read")
        e.add_grouping_policy("alice", "data2_admin")

        report = analyze_policy_impact(
            e,
            [PolicyEdit.remove(("alice", "data2", "read"))],
            users={"alice"},
            resources={"data2"},
            actions={"read"},
        )

        # deleting the direct allow rule must not be reported as a revocation,
        # because alice is still allowed through the data2_admin role.
        self.assertEqual(report.revoked, [])
        self.assertEqual(report.newly_allowed, [])
        self.assertEqual(len(report.unchanged_allowed), 1)

        impact = report.unchanged_allowed[0]
        self.assertEqual(impact.request, ("alice", "data2", "read"))
        self.assertEqual(impact.before_explain, ["alice", "data2", "read"])
        self.assertEqual(impact.after_explain, ["data2_admin", "data2", "read"])

    def test_grouping_relation_indirect_revocation(self):
        e = get_enforcer()
        report = analyze_policy_impact(
            e,
            [PolicyEdit.remove(("alice", "data2_admin"), sec="g")],
            users={"alice"},
            resources={"data2"},
            actions={"read", "write"},
        )

        revoked = sorted(i.request for i in report.revoked)
        self.assertEqual(revoked, [("alice", "data2", "read"), ("alice", "data2", "write")])
        for impact in report.revoked:
            self.assertEqual(impact.before_explain[0], "data2_admin")
            self.assertEqual(impact.after_explain, [])

    def test_report_notes_finite_scope(self):
        e = get_enforcer()
        report = analyze_policy_impact(
            e,
            [],
            users={"alice"},
            resources={"data1"},
            actions={"read"},
        )

        self.assertIn("1 user(s) x 1 resource(s) x 1 action(s)", report.scope)
        self.assertTrue(any("finite request domain" in lim for lim in report.limitations))
        self.assertTrue(any("not modified" in lim for lim in report.limitations))
        self.assertIn("Scope:", report.summary())

    def test_enforcer_and_adapter_untouched(self):
        e = casbin.Enforcer(get_examples("rbac_model.conf"), FailingWriteAdapter())
        e.enable_auto_save(False)
        e.add_policy("alice", "data1", "read")
        e.add_grouping_policy("alice", "data2_admin")
        e.enable_auto_save(True)

        policies_before = [list(rule) for rule in e.get_policy()]
        grouping_before = [list(rule) for rule in e.get_grouping_policy()]

        report = analyze_policy_impact(
            e,
            [
                PolicyEdit.add(("eve", "data1", "read")),
                PolicyEdit.remove(("alice", "data2_admin"), sec="g"),
            ],
            users={"alice", "eve"},
            resources={"data1"},
            actions={"read"},
        )

        self.assertEqual([list(rule) for rule in e.get_policy()], policies_before)
        self.assertEqual([list(rule) for rule in e.get_grouping_policy()], grouping_before)
        self.assertEqual(report.policy_counts_before["p/p"], 1)
        self.assertEqual(report.policy_counts_before["g/g"], 1)
        self.assertEqual(report.policy_counts_after["p/p"], 2)
        self.assertEqual(report.policy_counts_after["g/g"], 0)

    def test_ineffective_edit_is_reported(self):
        e = get_enforcer()
        report = analyze_policy_impact(
            e,
            [PolicyEdit.remove(("nobody", "data9", "read"))],
            users={"alice"},
            resources={"data1"},
            actions={"read"},
        )

        self.assertEqual(len(report.ineffective_edits), 1)
        self.assertTrue(any("no effect" in lim for lim in report.limitations))
        self.assertEqual(report.changed, 0)

    def test_unstable_custom_function_is_flagged(self):
        seen = set()

        def flaky(a, b):
            if a in seen:
                return False
            seen.add(a)
            return True

        m = casbin.model.Model()
        m.load_model_from_text(
            """
            [request_definition]
            r = sub, obj, act

            [policy_definition]
            p = sub, obj, act

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r_sub == p_sub && flakyMatch(r_obj, p_obj) && r_act == p_act
            """
        )
        e = casbin.Enforcer(m)
        e.add_function("flakyMatch", flaky)
        e.add_policy("alice", "data1", "read")

        report = analyze_policy_impact(
            e,
            [],
            users={"alice"},
            resources={"data1"},
            actions={"read"},
        )
        self.assertTrue(any("flakyMatch" in lim for lim in report.limitations))
        self.assertTrue(any("inconsistent" in lim for lim in report.limitations))

    def test_custom_function_assumption_is_documented(self):
        e = get_enforcer()
        e.add_function("myMatch", lambda a, b: a == b)

        report = analyze_policy_impact(
            e,
            [],
            users={"alice"},
            resources={"data1"},
            actions={"read"},
        )
        self.assertTrue(any("deterministic" in lim for lim in report.limitations))

    def test_explicit_requests(self):
        e = get_enforcer()
        report = analyze_policy_impact(
            e,
            [PolicyEdit.add(("bob", "data1", "read"))],
            requests=[("bob", "data1", "read"), ("alice", "data1", "read")],
        )

        self.assertEqual(report.total_requests, 2)
        self.assertEqual([i.request for i in report.newly_allowed], [("bob", "data1", "read")])
        self.assertIn("explicitly provided", report.scope)
