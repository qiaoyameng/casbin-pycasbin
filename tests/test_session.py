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

import casbin
from tests.test_enforcer import TestCaseBase

DOMAIN_MODEL = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
"""


def get_enforcer():
    m = casbin.Model()
    m.load_model_from_text(DOMAIN_MODEL)
    return casbin.Enforcer(m)


class TestSession(TestCaseBase):
    def test_two_coexisting_sessions(self):
        e = get_enforcer()
        e.add_policy("applicant", "domain1", "purchase", "create")
        e.add_policy("approver", "domain1", "purchase", "approve")
        e.add_role_for_user_in_domain("alice", "applicant", "domain1")
        e.add_role_for_user_in_domain("alice", "approver", "domain1")

        s1 = e.create_session("alice", "domain1")
        s2 = e.create_session("alice", "domain1")
        e.activate_role(s1, "applicant")
        e.activate_role(s2, "approver")

        # each session only sees its own activated roles
        self.assertTrue(e.enforce_with_session(s1, "alice", "domain1", "purchase", "create"))
        self.assertFalse(e.enforce_with_session(s1, "alice", "domain1", "purchase", "approve"))
        self.assertTrue(e.enforce_with_session(s2, "alice", "domain1", "purchase", "approve"))
        self.assertFalse(e.enforce_with_session(s2, "alice", "domain1", "purchase", "create"))

        # sessions do not interfere with each other
        self.assertEqual(e.get_activated_roles(s1), ["applicant"])
        self.assertEqual(e.get_activated_roles(s2), ["approver"])

        # a session only affects its own user's requests
        e.add_role_for_user_in_domain("bob", "approver", "domain1")
        self.assertTrue(e.enforce_with_session(s1, "bob", "domain1", "purchase", "approve"))

    def test_no_session_enforce_semantics_preserved(self):
        e = get_enforcer()
        e.add_policy("applicant", "domain1", "purchase", "create")
        e.add_policy("approver", "domain1", "purchase", "approve")
        e.add_role_for_user_in_domain("alice", "applicant", "domain1")
        e.add_role_for_user_in_domain("alice", "approver", "domain1")
        e.add_dsd_constraint({"applicant", "approver"}, 1)

        s = e.create_session("alice", "domain1")
        e.activate_role(s, "applicant")

        # plain enforce() is unaware of sessions and DSD constraints
        self.assertTrue(e.enforce("alice", "domain1", "purchase", "create"))
        self.assertTrue(e.enforce("alice", "domain1", "purchase", "approve"))

    def test_dsd_constraint(self):
        e = get_enforcer()
        e.add_policy("applicant", "domain1", "purchase", "create")
        e.add_policy("approver", "domain1", "purchase", "approve")
        e.add_role_for_user_in_domain("alice", "applicant", "domain1")
        e.add_role_for_user_in_domain("alice", "approver", "domain1")
        e.add_dsd_constraint({"applicant", "approver"}, 1)

        s = e.create_session("alice", "domain1")
        self.assertTrue(e.activate_role(s, "applicant"))
        # the error surfaces at activation time, not at enforce time
        with self.assertRaises(casbin.SessionError):
            e.activate_role(s, "approver")

        # deactivating frees a slot under the constraint
        e.deactivate_role(s, "applicant")
        self.assertTrue(e.activate_role(s, "approver"))
        self.assertTrue(e.enforce_with_session(s, "alice", "domain1", "purchase", "approve"))
        self.assertFalse(e.enforce_with_session(s, "alice", "domain1", "purchase", "create"))

    def test_dsd_constraint_with_inheritance(self):
        e = get_enforcer()
        e.add_policy("procurement_desk", "domain1", "purchase", "handle")
        # two surface-different roles, both inherit the conflicting position
        e.add_grouping_policy("requester_create", "procurement_desk", "domain1")
        e.add_grouping_policy("requester_approve", "procurement_desk", "domain1")
        e.add_role_for_user_in_domain("alice", "requester_create", "domain1")
        e.add_role_for_user_in_domain("alice", "requester_approve", "domain1")
        e.add_dsd_constraint({"procurement_desk"}, 1)

        s = e.create_session("alice", "domain1")
        self.assertTrue(e.activate_role(s, "requester_create"))
        # requester_approve looks different but inherits the same conflict position
        with self.assertRaises(casbin.SessionError):
            e.activate_role(s, "requester_approve")

        # inheritance also grants the permission through the activated role
        self.assertTrue(e.enforce_with_session(s, "alice", "domain1", "purchase", "handle"))

    def test_dsd_constraint_max_two(self):
        e = get_enforcer()
        for role in ("r1", "r2", "r3"):
            e.add_role_for_user_in_domain("alice", role, "domain1")
        e.add_dsd_constraint({"r1", "r2", "r3"}, 2)

        s = e.create_session("alice", "domain1")
        e.activate_role(s, "r1")
        e.activate_role(s, "r2")
        with self.assertRaises(casbin.SessionError):
            e.activate_role(s, "r3")

        # removing the constraint lifts the limit
        constraint_id = e.get_dsd_constraints()[0].id
        self.assertTrue(e.remove_dsd_constraint(constraint_id))
        self.assertTrue(e.activate_role(s, "r3"))

    def test_cross_domain_same_name_role(self):
        e = get_enforcer()
        e.add_policy("auditor", "domain1", "ledger", "read")
        e.add_policy("auditor", "domain2", "ledger", "write")
        e.add_role_for_user_in_domain("alice", "auditor", "domain1")
        e.add_role_for_user_in_domain("alice", "auditor", "domain2")

        s = e.create_session("alice", "domain1")
        e.activate_role(s, "auditor")

        # the activation in domain1 does not leak into domain2's same-name role
        self.assertTrue(e.enforce_with_session(s, "alice", "domain1", "ledger", "read"))
        self.assertFalse(e.enforce_with_session(s, "alice", "domain2", "ledger", "write"))

        # activation must come from roles owned in the session's domain:
        # bob owns "auditor" only in domain1, so a domain2 session rejects it
        e.add_role_for_user_in_domain("bob", "auditor", "domain1")
        s2 = e.create_session("bob", "domain2")
        with self.assertRaises(casbin.SessionError):
            e.activate_role(s2, "auditor")

    def test_activation_requires_ownership(self):
        e = get_enforcer()
        e.add_role_for_user_in_domain("alice", "applicant", "domain1")

        s = e.create_session("alice", "domain1")
        with self.assertRaises(casbin.SessionError):
            e.activate_role(s, "approver")
        self.assertEqual(e.get_activated_roles(s), [])

    def test_revoked_assignment_stops_granting_permission(self):
        e = get_enforcer()
        e.add_policy("approver", "domain1", "purchase", "approve")
        e.add_role_for_user_in_domain("alice", "approver", "domain1")

        s = e.create_session("alice", "domain1")
        e.activate_role(s, "approver")
        self.assertTrue(e.enforce_with_session(s, "alice", "domain1", "purchase", "approve"))

        # revoke the assignment: the old activation state no longer helps
        e.delete_roles_for_user_in_domain("alice", "approver", "domain1")
        self.assertFalse(e.enforce_with_session(s, "alice", "domain1", "purchase", "approve"))

        # and the role can no longer be (re-)activated either
        e.deactivate_role(s, "approver")
        with self.assertRaises(casbin.SessionError):
            e.activate_role(s, "approver")

    def test_dropped_session(self):
        e = get_enforcer()
        e.add_policy("applicant", "domain1", "purchase", "create")
        e.add_role_for_user_in_domain("alice", "applicant", "domain1")

        s = e.create_session("alice", "domain1")
        e.activate_role(s, "applicant")
        self.assertTrue(e.drop_session(s))

        with self.assertRaises(casbin.SessionError):
            e.enforce_with_session(s, "alice", "domain1", "purchase", "create")
        with self.assertRaises(casbin.SessionError):
            e.activate_role(s, "applicant")

        # other sessions are unaffected
        s2 = e.create_session("alice", "domain1")
        e.activate_role(s2, "applicant")
        self.assertTrue(e.enforce_with_session(s2, "alice", "domain1", "purchase", "create"))
