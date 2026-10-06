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

from itertools import combinations
from unittest import TestCase

import casbin
from casbin.persist.adapters.string_adapter import StringAdapter
from casbin.util.role_inducer import induce_roles

RBAC_MODEL_TEXT = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ , _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""


def reference_optimum(users, permissions, allow, forbidden_pairs=()):
    """Brute-force reference: enumerates every role set to find the true
    lexicographic (role count, assignment edges) optimum."""
    grants = {user: set() for user in users}
    for user, perm in allow:
        grants[user].add(perm)
    forbidden = [frozenset(pair) for pair in forbidden_pairs]
    candidates = []
    for size in range(1, len(permissions) + 1):
        for combo in combinations(permissions, size):
            role = frozenset(combo)
            if not any(pair <= role for pair in forbidden):
                candidates.append(role)
    for role_count in range(0, len(candidates) + 1):
        best_edges = None
        for role_set in combinations(candidates, role_count):
            edges = 0
            feasible = True
            for user in users:
                target = grants[user]
                usable = [r for r in role_set if r <= target]
                min_cover = None
                for cover_size in range(0, len(usable) + 1):
                    if any(
                        (set().union(*cover) if cover else set()) == target
                        for cover in combinations(usable, cover_size)
                    ):
                        min_cover = cover_size
                        break
                if min_cover is None:
                    feasible = False
                    break
                edges += min_cover
            if feasible and (best_edges is None or edges < best_edges):
                best_edges = edges
        if best_edges is not None:
            return (role_count, best_edges)
    return None


def make_enforcer(result):
    model = casbin.Model()
    model.load_model_from_text(RBAC_MODEL_TEXT)
    return casbin.Enforcer(model, StringAdapter(result.to_policy_text()))


def assert_exact_enforcement(test_case, result, users, permissions, allow):
    """Loads the induced policies into an independent enforcer and checks
    every cell of the user x permission grid."""
    granted = set(allow)
    enforcer = make_enforcer(result)
    for user in users:
        for perm in permissions:
            test_case.assertEqual(
                (user, perm) in granted,
                enforcer.enforce(user, perm, "access"),
                f"cell ({user}, {perm})",
            )
    test_case.assertFalse(enforcer.enforce("mallory", permissions[0], "access"))


class TestRoleInducer(TestCase):
    def test_shared_permission_groups(self):
        users = ["alice", "bob", "carol", "dave", "erin"]
        permissions = ["read", "write", "export"]
        allow = [
            ("alice", "read"),
            ("alice", "write"),
            ("bob", "read"),
            ("bob", "write"),
            ("carol", "read"),
            ("carol", "write"),
            ("carol", "export"),
            ("dave", "export"),
        ]
        result = induce_roles(users, permissions, allow)

        self.assertTrue(result.proven_optimal)
        self.assertFalse(result.budget_exhausted)
        # Two shared permission groups suffice: {read, write} and {export}.
        self.assertEqual((2, 5), result.objective)
        self.assertEqual(
            {frozenset({"read", "write"}), frozenset({"export"})},
            {role.permissions for role in result.roles},
        )
        for user in users:
            expected = {perm for u, perm in allow if u == user}
            self.assertEqual(expected, set(result.effective_permissions(user)))
        self.assertEqual([], result.assignments["erin"])

    def test_matches_brute_force_reference(self):
        permissions = ["p1", "p2", "p3"]
        matrices = [
            [
                ("alice", "p1"),
                ("alice", "p2"),
                ("bob", "p2"),
                ("bob", "p3"),
                ("carol", "p1"),
                ("carol", "p3"),
            ],
            [
                ("alice", "p1"),
                ("bob", "p1"),
                ("bob", "p2"),
                ("carol", "p1"),
                ("carol", "p2"),
                ("carol", "p3"),
            ],
            [
                ("alice", "p1"),
                ("alice", "p3"),
                ("bob", "p2"),
                ("bob", "p3"),
                ("carol", "p1"),
                ("carol", "p2"),
            ],
        ]
        for allow in matrices:
            users = sorted({u for u, _ in allow})
            result = induce_roles(users, permissions, allow)
            self.assertTrue(result.proven_optimal)
            self.assertEqual(
                reference_optimum(users, permissions, allow),
                result.objective,
                f"matrix {allow}",
            )
            assert_exact_enforcement(self, result, users, permissions, allow)

    def test_forbidden_pairs(self):
        users = ["alice", "bob"]
        permissions = ["read", "write"]
        allow = [
            ("alice", "read"),
            ("alice", "write"),
            ("bob", "read"),
            ("bob", "write"),
        ]
        unconstrained = induce_roles(users, permissions, allow)
        self.assertEqual((1, 2), unconstrained.objective)

        constrained = induce_roles(
            users, permissions, allow, forbidden_pairs=[("read", "write")]
        )
        self.assertTrue(constrained.proven_optimal)
        self.assertEqual((2, 4), constrained.objective)
        for role in constrained.roles:
            self.assertEqual(1, len(role.permissions))
        self.assertEqual(
            reference_optimum(users, permissions, allow, [("read", "write")]),
            constrained.objective,
        )
        assert_exact_enforcement(self, constrained, users, permissions, allow)

    def test_node_budget_marks_unproven_result(self):
        users = ["u1", "u2", "u3", "u4"]
        permissions = ["p1", "p2", "p3", "p4"]
        allow = [
            ("u1", "p1"),
            ("u1", "p2"),
            ("u1", "p3"),
            ("u2", "p2"),
            ("u2", "p3"),
            ("u2", "p4"),
            ("u3", "p1"),
            ("u3", "p3"),
            ("u3", "p4"),
            ("u4", "p1"),
            ("u4", "p2"),
            ("u4", "p4"),
        ]
        limited = induce_roles(users, permissions, allow, node_budget=0)
        self.assertFalse(limited.proven_optimal)
        self.assertTrue(limited.budget_exhausted)
        # A budget-limited plan is still exact on every cell.
        assert_exact_enforcement(self, limited, users, permissions, allow)

        proven = induce_roles(users, permissions, allow)
        self.assertTrue(proven.proven_optimal)
        self.assertFalse(proven.budget_exhausted)
        self.assertLessEqual(proven.objective, limited.objective)
        self.assertEqual(
            reference_optimum(users, permissions, allow), proven.objective
        )

    def test_enforcer_round_trip(self):
        users = ["alice", "bob", "carol", "dave", "erin"]
        permissions = ["read", "write", "export"]
        allow = [
            ("alice", "read"),
            ("alice", "write"),
            ("bob", "read"),
            ("bob", "write"),
            ("carol", "read"),
            ("carol", "write"),
            ("carol", "export"),
            ("dave", "export"),
        ]
        result = induce_roles(users, permissions, allow)
        enforcer = make_enforcer(result)

        # Policy shape matches the induced plan exactly.
        self.assertEqual(
            sum(len(role.permissions) for role in result.roles),
            len(enforcer.get_policy()),
        )
        self.assertEqual(
            result.assignment_edge_count, len(enforcer.get_grouping_policy())
        )
        assert_exact_enforcement(self, result, users, permissions, allow)

    def test_input_validation(self):
        with self.assertRaises(ValueError):
            induce_roles(["alice"], ["p1"], [("mallory", "p1")])
        with self.assertRaises(ValueError):
            induce_roles(["alice"], ["p1"], [("alice", "p9")])
        with self.assertRaises(ValueError):
            induce_roles(
                ["alice"], ["p1"], [("alice", "p1")], forbidden_pairs=[("p1", "p9")]
            )
        with self.assertRaises(ValueError):
            induce_roles(
                ["alice"],
                ["p1", "p2"],
                [("alice", "p1")],
                forbidden_pairs=[("p1", "p1", "p2")],
            )
        with self.assertRaises(ValueError):
            induce_roles(["alice", "alice"], ["p1"], [("alice", "p1")])
        # A permission forbidden with itself can never be granted exactly.
        with self.assertRaises(ValueError):
            induce_roles(
                ["alice"], ["p1"], [("alice", "p1")], forbidden_pairs=[("p1", "p1")]
            )
