# Copyright 2026 The casbin Authors. All Rights Reserved.
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

from itertools import combinations, product
from unittest import TestCase

import casbin
from casbin.rbac_mining import induce_roles

RBAC_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ , _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == r.act
""".replace("r.act == r.act", "r.act == p.act")

ACTION = "read"


def brute_force_optimum(users, permissions, grants, forbidden_pairs=()):
    """Enumerate every compatible role family for tiny matrices (<=4 perms)."""
    perm_index = {name: i for i, name in enumerate(permissions)}
    forbidden_index = [0] * len(permissions)
    for left, right in forbidden_pairs:
        i, j = perm_index[left], perm_index[right]
        forbidden_index[i] |= 1 << j
        forbidden_index[j] |= 1 << i

    rows = [0] * len(users)
    for user, permission in grants:
        rows[users.index(user)] |= 1 << perm_index[permission]

    def compatible(mask):
        bits = mask
        while bits:
            bit = bits & -bits
            i = bit.bit_length() - 1
            if forbidden_index[i] & mask:
                return False
            bits ^= bit
        return True

    candidate_roles = [
        mask
        for mask in range(1, 1 << len(permissions))
        if compatible(mask)
    ]

    best = [None, None]

    def min_edges(row, family):
        result = [None]

        def cover(remaining, used_edges):
            if result[0] is not None and used_edges >= result[0]:
                return
            if remaining == 0:
                result[0] = used_edges
                return
            for role_mask in family:
                if role_mask & remaining and role_mask & ~row == 0:
                    cover(remaining & ~role_mask, used_edges + 1)

        cover(row, 0)
        return result[0]

    def evaluate(family):
        total = 0
        for row in rows:
            if row == 0:
                continue
            local_best = min_edges(row, family)
            if local_best is None:
                return None
            total += local_best
        return total

    def choose(start, family):
        edges = evaluate(family)
        if edges is not None:
            if best[0] is None or (len(family), edges) < (best[0], best[1]):
                best[0] = len(family)
                best[1] = edges
        # A family larger than the best role count can only improve the
        # result by having fewer edges; still needs enumeration up to the
        # trivial singleton upper bound (one role per permission).
        for idx in range(start, len(candidate_roles)):
            if best[0] is not None and len(family) + 1 > best[0]:
                continue
            family.append(candidate_roles[idx])
            choose(idx + 1, family)
            family.pop()

    choose(0, [])
    return best[0], best[1]


def build_independent_enforcer(result):
    model = casbin.Model()
    model.load_model_from_text(RBAC_MODEL)
    enforcer = casbin.Enforcer(model, None)
    if result.p_rules:
        enforcer.add_policies(list(result.p_rules))
    if result.g_rules:
        enforcer.add_grouping_policies(list(result.g_rules))
    return enforcer


def effective_matrix(users, permissions, result, action=ACTION):
    enforcer = build_independent_enforcer(result)
    matrix = {}
    for user, permission in product(users, permissions):
        matrix[user, permission] = bool(
            enforcer.enforce(user, permission, action)
        )
    return matrix, enforcer


class TestRoleInducer(TestCase):
    def assert_matrix_exact(self, users, permissions, grants, result):
        expected = {(user, perm): False for user in users for perm in permissions}
        for user, perm in grants:
            expected[user, perm] = True
        actual, _ = effective_matrix(users, permissions, result)
        self.assertEqual(actual, expected)
        for role in result.roles:
            role_permissions = set(role.permissions)
            for user in users:
                user_permissions = {
                    perm for (u, perm) in grants if u == user
                }
                if any(
                    rule == (user, role.name) for rule in result.g_rules
                ):
                    self.assertTrue(role_permissions.issubset(user_permissions))

    def assert_assignment_exact(self, users, permissions, grants, result):
        granted = {(user, perm) for user, perm in grants}
        role_permissions = {
            role.name: set(role.permissions) for role in result.roles
        }
        member_roles = {user: set() for user in users}
        for user, role_name in result.g_rules:
            self.assertIn(user, member_roles)
            self.assertIn(role_name, role_permissions)
            member_roles[user].add(role_name)
        for user in users:
            effective = set()
            for role_name in member_roles[user]:
                effective |= role_permissions[role_name]
            expected = {
                perm for perm in permissions if (user, perm) in granted
            }
            self.assertEqual(effective, expected)

    def test_shared_two_permissions_matrix(self):
        users = ("alice", "bob", "carol")
        permissions = ("doc_read", "doc_write")
        grants = (
            ("alice", "doc_read"),
            ("bob", "doc_read"),
            ("bob", "doc_write"),
            ("carol", "doc_write"),
        )
        result = induce_roles(users, permissions, grants)
        self.assertTrue(result.optimal, result.status)
        self.assertEqual(result.status, "optimal")
        self.assertEqual(result.role_count, 2)
        self.assertEqual(result.assignment_edge_count, 4)
        self.assertEqual(
            sorted(role.permissions for role in result.roles),
            [("doc_read",), ("doc_write",)],
        )
        self.assert_matrix_exact(users, permissions, grants, result)
        self.assertEqual(
            sorted(result.p_rules),
            [
                ("role_0", "doc_read", "read"),
                ("role_1", "doc_write", "read"),
            ],
        )

    def test_brute_force_reference_smaller_matrix(self):
        users = ("u0", "u1")
        permissions = ("a", "b")
        grants = (
            ("u0", "a"),
            ("u1", "a"),
            ("u1", "b"),
        )
        ref_roles, ref_edges = brute_force_optimum(
            users, permissions, grants
        )
        result = induce_roles(users, permissions, grants)
        self.assertTrue(result.optimal)
        self.assertEqual(result.role_count, ref_roles)
        self.assertEqual(result.assignment_edge_count, ref_edges)
        # roles {a} and {ab}: u0->{a}, u1->{ab} -> 2 roles, 2 edges
        self.assertEqual((ref_roles, ref_edges), (2, 2))
        self.assert_matrix_exact(users, permissions, grants, result)

    def test_brute_force_reference_all_two_by_two_patterns(self):
        users = ("u0", "u1", "u2")
        permissions = ("a", "b")
        grant_options = tuple(product(users, permissions))
        for mask in range(1 << len(grant_options)):
            grants = tuple(
                grant
                for i, grant in enumerate(grant_options)
                if mask & (1 << i)
            )
            ref_roles, ref_edges = brute_force_optimum(
                users, permissions, grants
            )
            result = induce_roles(
                users, permissions, grants, node_budget=10 ** 6
            )
            self.assertTrue(result.optimal)
            self.assertEqual(result.role_count, ref_roles)
            self.assertEqual(result.assignment_edge_count, ref_edges)
            self.assert_assignment_exact(users, permissions, grants, result)

    def test_forbidden_pair_changes_optimum(self):
        users = ("alice", "bob")
        permissions = ("doc_read", "doc_write")
        grants = (
            ("alice", "doc_read"),
            ("alice", "doc_write"),
            ("bob", "doc_read"),
            ("bob", "doc_write"),
        )
        unrestricted = induce_roles(users, permissions, grants)
        self.assertEqual(unrestricted.role_count, 1)
        self.assertEqual(unrestricted.assignment_edge_count, 2)
        self.assertTrue(unrestricted.optimal)
        self.assert_matrix_exact(users, permissions, grants, unrestricted)

        forbidden = induce_roles(
            users,
            permissions,
            grants,
            forbidden_pairs=(("doc_read", "doc_write"),),
        )
        self.assertTrue(forbidden.optimal)
        self.assertEqual(forbidden.role_count, 2)
        self.assertEqual(forbidden.assignment_edge_count, 4)
        for role in forbidden.roles:
            self.assertLessEqual(len(role.permissions), 1)
        self.assertEqual(
            forbidden.forbidden_pairs,
            (("doc_read", "doc_write"),),
        )
        self.assert_matrix_exact(users, permissions, grants, forbidden)

    def test_budget_exhaustion_marked_unproven(self):
        users = tuple("u{}".format(i) for i in range(6))
        permissions = tuple("p{}".format(i) for i in range(6))
        grants = tuple(
            (user, permission)
            for user in users
            for permission in permissions
            if (int(user[1]) * 3 + int(permission[1:])) % 2 == 0
        )
        result = induce_roles(
            users, permissions, grants, node_budget=3
        )
        self.assertFalse(result.optimal)
        self.assertEqual(result.status, "budget_exhausted")
        self.assertLessEqual(result.nodes_used, result.node_budget)
        self.assertGreater(result.role_count, 0)
        self.assert_matrix_exact(users, permissions, grants, result)

        proven = induce_roles(
            users, permissions, grants, node_budget=10 ** 6
        )
        self.assertTrue(proven.optimal)
        self.assertEqual(proven.status, "optimal")
        self.assertEqual(proven.role_count, result.role_count)
        self.assertEqual(
            proven.assignment_edge_count, result.assignment_edge_count
        )
        self.assert_matrix_exact(users, permissions, grants, proven)

    def test_enlarged_budget_proves_optimum_matches_reference(self):
        users = tuple("u{}".format(i) for i in range(3))
        permissions = tuple("p{}".format(i) for i in range(4))
        grants = tuple(
            (user, permission)
            for user in users
            for permission in permissions
            if (int(user[1]) * 2 + int(permission[1:])) % 3 != 1
        )
        ref_roles, ref_edges = brute_force_optimum(
            users, permissions, grants
        )
        result = induce_roles(
            users, permissions, grants, node_budget=10 ** 7
        )
        self.assertTrue(result.optimal)
        self.assertEqual(result.role_count, ref_roles)
        self.assertEqual(result.assignment_edge_count, ref_edges)
        self.assert_matrix_exact(users, permissions, grants, result)

    def test_empty_matrix(self):
        result = induce_roles((), ("a", "b"), ())
        self.assertTrue(result.optimal)
        self.assertEqual(result.role_count, 0)
        self.assertEqual(result.p_rules, ())
        self.assertEqual(result.g_rules, ())

        result_with_user = induce_roles(
            ("alice",), ("a", "b"), ()
        )
        self.assertTrue(result_with_user.optimal)
        self.assertEqual(result_with_user.role_count, 0)
        self.assert_matrix_exact(("alice",), ("a", "b"), (), result_with_user)

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            induce_roles(("a",), ("p",), (("x", "p"),))
        with self.assertRaises(ValueError):
            induce_roles(("a",), ("p",), (("a", "q"),))
        with self.assertRaises(ValueError):
            induce_roles(
                ("a",), ("p", "q"), (), forbidden_pairs=(("p", "x"),)
            )
        with self.assertRaises(ValueError):
            induce_roles(
                ("a",), ("p",), (), forbidden_pairs=(("p", "p"),)
            )
        with self.assertRaises(ValueError):
            induce_roles(("a", "a"), ("p",), ())
        with self.assertRaises(ValueError):
            induce_roles(("a",), ("p",), (), objective="edges_first")
        with self.assertRaises(ValueError):
            induce_roles(("a",), ("p",), (), node_budget=0)
