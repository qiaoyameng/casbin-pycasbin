from unittest import TestCase

import casbin
from casbin.restricted_management import (
    GrantScope,
    InvalidChangeError,
    OutOfScopeError,
    PolicyChange,
    UnsupportedModelError,
    apply_restricted_batch,
)

RBAC_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""

DENY_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""

KEYMATCH_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch(r.obj, p.obj) && r.act == p.act
"""

REGEX_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && regexMatch(r.act, p.act)
"""


class RecordingAdapter(casbin.persist.Adapter):
    """In-memory adapter that records every write the enforcer attempts."""

    def __init__(self):
        self.calls = []

    def load_policy(self, model):
        pass

    def save_policy(self, model):
        pass

    def add_policy(self, sec, ptype, rule):
        self.calls.append(("add", sec, ptype, list(rule)))

    def remove_policy(self, sec, ptype, rule):
        self.calls.append(("remove", sec, ptype, list(rule)))

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        self.calls.append(("remove_filtered", sec, ptype, field_index, list(field_values)))


def make_enforcer(model_text, rules=()):
    model = casbin.Model()
    model.load_model_from_text(model_text)
    adapter = RecordingAdapter()
    enforcer = casbin.Enforcer(model, adapter)
    for sec, ptype, rule in rules:
        enforcer.model.add_policy(sec, ptype, rule)
    enforcer.build_role_links()
    adapter.calls.clear()
    return enforcer, adapter


class TestRestrictedManagement(TestCase):
    def test_in_scope_batch_is_applied(self):
        e, adapter = make_enforcer(RBAC_MODEL, [("p", "p", ["role_admin", "secret_data", "read"])])
        scope = GrantScope(subjects=["alice", "role_t1"], objects=["data1"], actions=["read"])

        result = apply_restricted_batch(
            e,
            scope,
            [
                PolicyChange("add", "p", "p", ["role_t1", "data1", "read"]),
                PolicyChange("add", "g", "g", ["alice", "role_t1"]),
            ],
        )

        self.assertTrue(result)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertEqual(len(adapter.calls), 2)

    def test_direct_out_of_scope_add_rejected(self):
        e, adapter = make_enforcer(RBAC_MODEL)
        scope = GrantScope(subjects=["alice"], objects=["data1"], actions=["read"])

        with self.assertRaises(OutOfScopeError) as ctx:
            apply_restricted_batch(e, scope, [("add", "p", "p", ["alice", "data9", "read"])])

        self.assertEqual(ctx.exception.request, ("alice", "data9", "read"))
        self.assertFalse(e.has_policy("alice", "data9", "read"))
        self.assertEqual(adapter.calls, [])

    def test_role_chain_escape_rejected(self):
        # Every direct rule in the batch only mentions in-scope names, but the
        # composed role chain hands alice the pre-existing admin permissions.
        e, adapter = make_enforcer(RBAC_MODEL, [("p", "p", ["role_admin", "secret_data", "read"])])
        scope = GrantScope(subjects=["alice", "role_t1"], objects=["data1"], actions=["read"])

        batch = [
            ("add", "p", "p", ["alice", "data1", "read"]),
            ("add", "g", "g", ["alice", "role_admin"]),
        ]
        with self.assertRaises(OutOfScopeError) as ctx:
            apply_restricted_batch(e, scope, batch)

        self.assertEqual(ctx.exception.request, ("alice", "secret_data", "read"))
        # One failing change rejects the whole batch: nothing was applied.
        self.assertFalse(e.has_policy("alice", "data1", "read"))
        self.assertFalse(e.has_grouping_policy("alice", "role_admin"))
        self.assertEqual(adapter.calls, [])

    def test_indirect_role_chain_escape_rejected(self):
        # The escape goes through a freshly created role: each single rule
        # looks tenant-local, the composed chain is not.
        e, adapter = make_enforcer(RBAC_MODEL, [("p", "p", ["role_admin", "secret_data", "read"])])
        scope = GrantScope(subjects=["alice", "role_t1"], objects=["data1"], actions=["read"])

        batch = [
            ("add", "p", "p", ["role_t1", "data1", "read"]),
            ("add", "g", "g", ["alice", "role_t1"]),
            ("add", "g", "g", ["role_t1", "role_admin"]),
        ]
        with self.assertRaises(OutOfScopeError) as ctx:
            apply_restricted_batch(e, scope, batch)

        self.assertEqual(ctx.exception.request, ("alice", "secret_data", "read"))
        self.assertFalse(e.has_policy("role_t1", "data1", "read"))
        self.assertEqual(adapter.calls, [])

    def test_deny_removal_expansion_rejected(self):
        e, adapter = make_enforcer(
            DENY_MODEL,
            [
                ("p", "p", ["alice", "data1", "read", "allow"]),
                ("p", "p", ["alice", "data2", "read", "allow"]),
                ("p", "p", ["alice", "data2", "read", "deny"]),
            ],
        )
        scope = GrantScope(subjects=["alice"], objects=["data1"], actions=["read"])

        with self.assertRaises(OutOfScopeError) as ctx:
            apply_restricted_batch(e, scope, [("remove", "p", "p", ["alice", "data2", "read", "deny"])])

        self.assertEqual(ctx.exception.request, ("alice", "data2", "read"))
        self.assertTrue(e.has_policy("alice", "data2", "read", "deny"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertEqual(adapter.calls, [])

    def test_deny_removal_within_scope_allowed(self):
        e, adapter = make_enforcer(
            DENY_MODEL,
            [
                ("p", "p", ["alice", "data2", "read", "allow"]),
                ("p", "p", ["alice", "data2", "read", "deny"]),
            ],
        )
        scope = GrantScope(subjects=["alice"], objects=["data2"], actions=["read"])

        result = apply_restricted_batch(e, scope, [("remove", "p", "p", ["alice", "data2", "read", "deny"])])

        self.assertTrue(result)
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertEqual(len(adapter.calls), 1)

    def test_wildcard_expansion_rejected(self):
        e, adapter = make_enforcer(KEYMATCH_MODEL)
        scope = GrantScope(subjects=["alice"], objects=["/data/1"], actions=["GET"])

        with self.assertRaises(OutOfScopeError) as ctx:
            apply_restricted_batch(e, scope, [("add", "p", "p", ["alice", "/data/*", "GET"])])

        sub, obj, act = ctx.exception.request
        self.assertEqual((sub, act), ("alice", "GET"))
        self.assertTrue(obj.startswith("/data/"))
        self.assertNotEqual(obj, "/data/1")
        self.assertFalse(e.has_policy("alice", "/data/*", "GET"))
        self.assertEqual(adapter.calls, [])

    def test_exact_rule_within_wildcard_model_allowed(self):
        e, adapter = make_enforcer(KEYMATCH_MODEL)
        scope = GrantScope(subjects=["alice"], objects=["/data/1"], actions=["GET"])

        result = apply_restricted_batch(e, scope, [("add", "p", "p", ["alice", "/data/1", "GET"])])

        self.assertTrue(result)
        self.assertTrue(e.enforce("alice", "/data/1", "GET"))
        self.assertEqual(len(adapter.calls), 1)

    def test_unsupported_matcher_rejected(self):
        e, adapter = make_enforcer(REGEX_MODEL)
        scope = GrantScope(subjects=["alice"], objects=["data1"], actions=["read"])

        with self.assertRaises(UnsupportedModelError) as ctx:
            apply_restricted_batch(e, scope, [("add", "p", "p", ["alice", "data1", "read"])])

        self.assertIn("regexMatch", str(ctx.exception))
        self.assertEqual(adapter.calls, [])

    def test_invalid_change_rejects_whole_batch(self):
        e, adapter = make_enforcer(RBAC_MODEL)
        scope = GrantScope(subjects=["alice"], objects=["data1"], actions=["read"])

        batch = [
            ("add", "p", "p", ["alice", "data1", "read"]),
            ("remove", "p", "p", ["alice", "data2", "read"]),
        ]
        with self.assertRaises(InvalidChangeError):
            apply_restricted_batch(e, scope, batch)

        self.assertFalse(e.has_policy("alice", "data1", "read"))
        self.assertEqual(adapter.calls, [])

    def test_permission_reduction_allowed(self):
        e, adapter = make_enforcer(RBAC_MODEL, [("p", "p", ["alice", "data1", "read"])])
        scope = GrantScope(subjects=["alice"], objects=["data1"], actions=["read"])

        result = apply_restricted_batch(e, scope, [("remove", "p", "p", ["alice", "data1", "read"])])

        self.assertTrue(result)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertEqual(len(adapter.calls), 1)

    def test_empty_batch_is_noop(self):
        e, adapter = make_enforcer(RBAC_MODEL)
        scope = GrantScope(subjects=["alice"], objects=["data1"], actions=["read"])

        self.assertTrue(apply_restricted_batch(e, scope, []))
        self.assertEqual(adapter.calls, [])

    def test_universe_size_limit(self):
        e, adapter = make_enforcer(RBAC_MODEL)
        scope = GrantScope(subjects=["alice"], objects=["data1"], actions=["read"])

        with self.assertRaises(UnsupportedModelError):
            apply_restricted_batch(e, scope, [("add", "p", "p", ["alice", "data1", "read"])], max_requests=1)

        self.assertEqual(adapter.calls, [])
