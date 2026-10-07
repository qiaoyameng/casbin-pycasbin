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

import unittest

import casbin
from casbin.persist import Adapter
from casbin.restricted_management import (
    AdminScope,
    PolicyChange,
    ScopedPolicyManager,
    ScopeViolationError,
    UnsupportedModelError,
    apply_scoped_changes,
)

RBAC_DENY_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p_eft == allow)) && !some(where (p_eft == deny))

[matchers]
m = g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act
"""

KEYMATCH_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p_eft == allow))

[matchers]
m = r_sub == p_sub && keyMatch(r_obj, p_obj) && r_act == p_act
"""

REGEX_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p_eft == allow))

[matchers]
m = r_sub == p_sub && r_obj == p_obj && regexMatch(r_act, p_act)
"""

DOMAINS_MODEL = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p_eft == allow))

[matchers]
m = g(r_sub, p_sub, r_dom) && r_dom == p_dom && r_obj == p_obj && r_act == p_act
"""

ABAC_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p_eft == allow))

[matchers]
m = r_sub == p_sub && r_obj == p_obj && r_act == p_act && r_sub_age > 18
"""


class RecordingAdapter(Adapter):
    """adapter spy proving that nothing is persisted before verification."""

    def __init__(self):
        self.calls = []

    def load_policy(self, model):
        pass

    def save_policy(self, model):
        self.calls.append(("save_policy",))

    def add_policy(self, sec, ptype, rule):
        self.calls.append(("add_policy", sec, ptype, list(rule)))

    def remove_policy(self, sec, ptype, rule):
        self.calls.append(("remove_policy", sec, ptype, list(rule)))

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        self.calls.append(("remove_filtered_policy", sec, ptype))


def make_enforcer(model_text, adapter=None, rules=(), grouping_rules=()):
    model = casbin.Model()
    model.load_model_from_text(model_text)
    enforcer = casbin.Enforcer(model, adapter)
    for rule in rules:
        enforcer.add_policy(*rule)
    for rule in grouping_rules:
        enforcer.add_grouping_policy(*rule)
    if adapter is not None:
        adapter.calls.clear()
    return enforcer


def make_scope(**kwargs):
    defaults = {"subjects": {"alice", "bob"}, "objects": {"data1", "data2"}, "actions": {"read", "write"}}
    defaults.update(kwargs)
    return AdminScope(**defaults)


class TestScopedPolicyManager(unittest.TestCase):
    def test_legitimate_batch_applies(self):
        adapter = RecordingAdapter()
        enforcer = make_enforcer(RBAC_DENY_MODEL, adapter=adapter)
        manager = ScopedPolicyManager(enforcer, make_scope())

        applied = manager.apply(
            [
                PolicyChange.add_policy(["role1", "data2", "read", "allow"]),
                PolicyChange.add_grouping_policy(["bob", "role1"]),
            ]
        )

        self.assertTrue(applied)
        self.assertTrue(enforcer.enforce("bob", "data2", "read"))
        self.assertEqual(2, len(adapter.calls))
        self.assertEqual("add_policy", adapter.calls[0][0])

    def test_role_chain_escape_rejected(self):
        # the direct rules of the batch are all legal (in-scope subject,
        # in-scope object), but the new role already inherits admin_role,
        # so the composed role chain grants alice secret_data.
        adapter = RecordingAdapter()
        enforcer = make_enforcer(
            RBAC_DENY_MODEL,
            adapter=adapter,
            rules=[["admin_role", "secret_data", "read", "allow"]],
            grouping_rules=[["role1", "admin_role"]],
        )
        manager = ScopedPolicyManager(enforcer, make_scope())

        with self.assertRaises(ScopeViolationError) as ctx:
            manager.apply(
                [
                    PolicyChange.add_policy(["role1", "data1", "read", "allow"]),
                    PolicyChange.add_grouping_policy(["alice", "role1"]),
                ]
            )

        self.assertIsNotNone(ctx.exception.witness)
        self.assertIn("secret_data", ctx.exception.witness)
        # the whole batch is rejected: nothing reached the model or adapter
        self.assertFalse(enforcer.has_policy("role1", "data1", "read", "allow"))
        self.assertFalse(enforcer.has_grouping_policy("alice", "role1"))
        self.assertEqual([], adapter.calls)

    def test_deny_removal_expansion_rejected(self):
        # removing a deny rule is a permission expansion: the underlying
        # allow rule grants alice an object outside the manageable set.
        adapter = RecordingAdapter()
        enforcer = make_enforcer(
            RBAC_DENY_MODEL,
            adapter=adapter,
            rules=[
                ["alice", "secret_data", "read", "allow"],
                ["alice", "secret_data", "read", "deny"],
            ],
        )
        self.assertFalse(enforcer.enforce("alice", "secret_data", "read"))
        manager = ScopedPolicyManager(enforcer, make_scope())

        with self.assertRaises(ScopeViolationError) as ctx:
            manager.apply(
                [PolicyChange.remove_policy(["alice", "secret_data", "read", "deny"])]
            )

        self.assertIn("secret_data", ctx.exception.witness)
        self.assertTrue(enforcer.has_policy("alice", "secret_data", "read", "deny"))
        self.assertFalse(enforcer.enforce("alice", "secret_data", "read"))
        self.assertEqual([], adapter.calls)

    def test_deny_removal_within_scope_applies(self):
        enforcer = make_enforcer(
            RBAC_DENY_MODEL,
            rules=[
                ["alice", "data1", "read", "allow"],
                ["alice", "data1", "read", "deny"],
            ],
        )
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))
        manager = ScopedPolicyManager(enforcer, make_scope())

        self.assertTrue(
            manager.apply(
                [PolicyChange.remove_policy(["alice", "data1", "read", "deny"])]
            )
        )
        self.assertTrue(enforcer.enforce("alice", "data1", "read"))

    def test_direct_out_of_scope_rule_rejected(self):
        enforcer = make_enforcer(RBAC_DENY_MODEL)
        manager = ScopedPolicyManager(enforcer, make_scope())

        with self.assertRaises(ScopeViolationError):
            manager.apply(
                [PolicyChange.add_policy(["alice", "secret_data", "read", "allow"])]
            )
        self.assertFalse(enforcer.has_policy("alice", "secret_data", "read", "allow"))

    def test_wildcard_pattern_escape_rejected(self):
        # keyMatch(r_obj, p_obj) with a wildcard pattern grants resources
        # outside any finite manageable object set.
        enforcer = make_enforcer(KEYMATCH_MODEL)
        manager = ScopedPolicyManager(
            enforcer, AdminScope(subjects={"alice"}, objects={"/data/1", "/data/2"}, actions={"read"})
        )

        with self.assertRaises(ScopeViolationError) as ctx:
            manager.apply([PolicyChange.add_policy(["alice", "/data/*", "read"])])

        self.assertIsNotNone(ctx.exception.witness)
        self.assertFalse(enforcer.has_policy("alice", "/data/*", "read"))

    def test_literal_pattern_within_scope_applies(self):
        enforcer = make_enforcer(KEYMATCH_MODEL)
        manager = ScopedPolicyManager(
            enforcer, AdminScope(subjects={"alice"}, objects={"/data/1"}, actions={"read"})
        )

        self.assertTrue(manager.apply([PolicyChange.add_policy(["alice", "/data/1", "read"])]))
        self.assertTrue(enforcer.enforce("alice", "/data/1", "read"))

    def test_unprovable_pattern_rejected_as_unsupported(self):
        # regexMatch cannot be proven finite (re.match prefix semantics);
        # the probes match nothing out of scope, so the batch is rejected
        # with a concrete not-supported reason instead of a witness.
        enforcer = make_enforcer(REGEX_MODEL)
        manager = ScopedPolicyManager(
            enforcer, AdminScope(subjects={"alice"}, objects={"data1"}, actions={"read", "write"})
        )

        with self.assertRaises(UnsupportedModelError):
            manager.apply([PolicyChange.add_policy(["alice", "data1", "read$|write$"])])
        self.assertFalse(enforcer.has_policy("alice", "data1", "read$|write$"))

    def test_regex_escape_finds_witness(self):
        enforcer = make_enforcer(REGEX_MODEL)
        manager = ScopedPolicyManager(
            enforcer, AdminScope(subjects={"alice"}, objects={"data1"}, actions={"read"})
        )

        with self.assertRaises(ScopeViolationError):
            manager.apply([PolicyChange.add_policy(["alice", "data1", "read.*"])])

    def test_unrestricted_dimension_allows_any_value(self):
        enforcer = make_enforcer(RBAC_DENY_MODEL)
        manager = ScopedPolicyManager(
            enforcer, AdminScope(subjects={"alice"}, objects={"data1"}, actions=None)
        )

        self.assertTrue(
            manager.apply([PolicyChange.add_policy(["alice", "data1", "any_action", "allow"])])
        )
        self.assertTrue(enforcer.enforce("alice", "data1", "any_action"))

    def test_batch_atomic_when_change_invalid(self):
        adapter = RecordingAdapter()
        enforcer = make_enforcer(RBAC_DENY_MODEL, adapter=adapter)
        manager = ScopedPolicyManager(enforcer, make_scope())

        with self.assertRaises(ValueError):
            manager.apply(
                [
                    PolicyChange.add_policy(["alice", "data1", "read", "allow"]),
                    PolicyChange.remove_policy(["alice", "no_such_obj", "read", "allow"]),
                ]
            )

        self.assertFalse(enforcer.has_policy("alice", "data1", "read", "allow"))
        self.assertEqual([], adapter.calls)

    def test_duplicate_add_rejected(self):
        enforcer = make_enforcer(RBAC_DENY_MODEL, rules=[["alice", "data1", "read", "allow"]])
        manager = ScopedPolicyManager(enforcer, make_scope())

        with self.assertRaises(ValueError):
            manager.apply([PolicyChange.add_policy(["alice", "data1", "read", "allow"])])

    def test_bad_rule_arity_rejected(self):
        enforcer = make_enforcer(RBAC_DENY_MODEL)
        manager = ScopedPolicyManager(enforcer, make_scope())

        with self.assertRaises(ValueError):
            manager.apply([PolicyChange.add_policy(["alice", "data1"])])

    def test_unsupported_matcher_rejected(self):
        enforcer = make_enforcer(ABAC_MODEL)
        manager = ScopedPolicyManager(enforcer, make_scope())

        with self.assertRaises(UnsupportedModelError):
            manager.apply([PolicyChange.add_policy(["alice", "data1", "read"])])

    def test_domains_model_scope_checked(self):
        enforcer = make_enforcer(DOMAINS_MODEL)
        scope = AdminScope(
            domains={"sub": {"alice"}, "dom": {"domain1"}, "obj": {"data1"}, "act": {"read"}}
        )
        manager = ScopedPolicyManager(enforcer, scope)

        with self.assertRaises(ScopeViolationError) as ctx:
            manager.apply([PolicyChange.add_policy(["alice", "domain2", "data1", "read"])])
        self.assertIn("domain2", ctx.exception.witness)

        self.assertTrue(
            manager.apply([PolicyChange.add_policy(["alice", "domain1", "data1", "read"])])
        )
        self.assertTrue(enforcer.enforce("alice", "domain1", "data1", "read"))

    def test_scope_missing_attribute_rejected(self):
        enforcer = make_enforcer(RBAC_DENY_MODEL)
        manager = ScopedPolicyManager(
            enforcer, AdminScope(subjects={"alice"}, objects={"data1"})
        )

        with self.assertRaises(UnsupportedModelError):
            manager.apply([PolicyChange.add_policy(["alice", "data1", "read", "allow"])])

    def test_max_checks_guard(self):
        enforcer = make_enforcer(RBAC_DENY_MODEL)
        manager = ScopedPolicyManager(enforcer, make_scope(), max_checks=1)

        with self.assertRaises(UnsupportedModelError):
            manager.apply([PolicyChange.add_policy(["alice", "data1", "read", "allow"])])

    def test_verify_does_not_modify_enforcer(self):
        adapter = RecordingAdapter()
        enforcer = make_enforcer(RBAC_DENY_MODEL, adapter=adapter)
        manager = ScopedPolicyManager(enforcer, make_scope())
        changes = [PolicyChange.add_policy(["alice", "data1", "read", "allow"])]

        self.assertTrue(manager.verify(changes))
        self.assertFalse(enforcer.has_policy("alice", "data1", "read", "allow"))
        self.assertEqual([], adapter.calls)

    def test_apply_scoped_changes_convenience(self):
        enforcer = make_enforcer(RBAC_DENY_MODEL)
        apply_scoped_changes(
            enforcer,
            make_scope(),
            [PolicyChange.add_policy(["alice", "data1", "write", "allow"])],
        )
        self.assertTrue(enforcer.enforce("alice", "data1", "write"))

    def test_grouping_removal_expansion_rejected(self):
        # removing a grouping rule can also expand permissions: the link was
        # keeping alice inside a role that carries a deny.
        enforcer = make_enforcer(
            RBAC_DENY_MODEL,
            rules=[
                ["alice", "secret_data", "read", "allow"],
                ["deny_role", "secret_data", "read", "deny"],
            ],
            grouping_rules=[["alice", "deny_role"]],
        )
        self.assertFalse(enforcer.enforce("alice", "secret_data", "read"))
        manager = ScopedPolicyManager(enforcer, make_scope())

        with self.assertRaises(ScopeViolationError) as ctx:
            manager.apply([PolicyChange.remove_grouping_policy(["alice", "deny_role"])])

        self.assertIn("secret_data", ctx.exception.witness)
        self.assertTrue(enforcer.has_grouping_policy("alice", "deny_role"))

    def test_add_out_of_scope_deny_applies(self):
        # adding a deny rule only shrinks the effective authorization, so it
        # is safe even for objects outside the manageable set.
        enforcer = make_enforcer(
            RBAC_DENY_MODEL, rules=[["alice", "secret_data", "read", "allow"]]
        )
        manager = ScopedPolicyManager(enforcer, make_scope())

        self.assertTrue(
            manager.apply(
                [PolicyChange.add_policy(["alice", "secret_data", "read", "deny"])]
            )
        )
        self.assertFalse(enforcer.enforce("alice", "secret_data", "read"))

    def test_remove_within_scope_applies(self):
        enforcer = make_enforcer(RBAC_DENY_MODEL, rules=[["alice", "data1", "read", "allow"]])
        manager = ScopedPolicyManager(enforcer, make_scope())

        self.assertTrue(
            manager.apply([PolicyChange.remove_policy(["alice", "data1", "read", "allow"])])
        )
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))


if __name__ == "__main__":
    unittest.main()
