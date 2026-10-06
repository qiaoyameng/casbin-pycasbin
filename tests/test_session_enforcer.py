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
from tests.test_enforcer import get_examples, TestCaseBase


def get_procurement_enforcer(test_case):
    """A procurement system: alice holds both the requester and the approver
    positions in dom1, and the same-named approver role also exists in dom2
    with different permissions. buyer/auditor inherit the conflicting
    positions in dom1."""
    e = test_case.get_enforcer(get_examples("rbac_with_domains_model.conf"))

    e.add_policy("requester", "dom1", "requisition", "create")
    e.add_policy("approver", "dom1", "requisition", "approve")
    e.add_policy("requester", "dom2", "report", "read")
    e.add_policy("approver", "dom2", "budget", "approve")

    e.add_role_for_user_in_domain("alice", "requester", "dom1")
    e.add_role_for_user_in_domain("alice", "approver", "dom1")
    e.add_role_for_user_in_domain("alice", "approver", "dom2")

    e.add_role_for_user_in_domain("buyer", "requester", "dom1")
    e.add_role_for_user_in_domain("auditor", "approver", "dom1")
    e.add_role_for_user_in_domain("bob", "buyer", "dom1")
    e.add_role_for_user_in_domain("bob", "auditor", "dom1")

    return e


class TestSessionEnforcer(TestCaseBase):
    def test_session_enforce_uses_activated_roles_only(self):
        e = get_procurement_enforcer(self)

        # Session-less enforce keeps the existing semantics: alice may use
        # every role she owns, even conflicting ones.
        self.assertTrue(e.enforce("alice", "dom1", "requisition", "create"))
        self.assertTrue(e.enforce("alice", "dom1", "requisition", "approve"))

        session = e.create_session("alice", "dom1")
        session.activate_role("requester")

        self.assertTrue(e.enforce_with_session(session, "alice", "dom1", "requisition", "create"))
        # The approver role is owned but not activated in this session.
        self.assertFalse(e.enforce_with_session(session, "alice", "dom1", "requisition", "approve"))

        session.activate_role("approver")
        self.assertTrue(e.enforce_with_session(session, "alice", "dom1", "requisition", "approve"))

        session.deactivate_role("requester")
        self.assertFalse(e.enforce_with_session(session, "alice", "dom1", "requisition", "create"))

    def test_activate_role_requires_ownership(self):
        e = get_procurement_enforcer(self)
        session = e.create_session("alice", "dom1")

        # alice does not own admin anywhere: the error surfaces at activation.
        with self.assertRaises(casbin.SessionError):
            session.activate_role("admin")

        # alice owns approver only in dom1/dom2, not requester in dom2.
        session_dom2 = e.create_session("alice", "dom2")
        with self.assertRaises(casbin.SessionError):
            session_dom2.activate_role("requester")
        session_dom2.activate_role("approver")
        self.assertEqual(session_dom2.get_activated_roles(), ["approver"])

    def test_dsd_constraint_blocks_conflicting_activation(self):
        e = get_procurement_enforcer(self)
        e.add_dsd_constraint({"requester", "approver"}, 1)

        session = e.create_session("alice", "dom1")
        session.activate_role("requester")
        # Same person, same session: cannot also approve.
        with self.assertRaises(casbin.SessionError):
            session.activate_role("approver")
        self.assertEqual(session.get_activated_roles(), ["requester"])

    def test_dsd_constraint_considers_role_inheritance(self):
        e = get_procurement_enforcer(self)
        e.add_dsd_constraint({"requester", "approver"}, 1)

        # buyer and auditor are surface-different roles, but they inherit the
        # conflicting requester/approver positions, so they must be blocked.
        session = e.create_session("bob", "dom1")
        session.activate_role("buyer")
        with self.assertRaises(casbin.SessionError):
            session.activate_role("auditor")

        # The inherited permissions still work through the activated role.
        self.assertTrue(e.enforce_with_session(session, "bob", "dom1", "requisition", "create"))
        self.assertFalse(e.enforce_with_session(session, "bob", "dom1", "requisition", "approve"))

    def test_sessions_are_independent(self):
        e = get_procurement_enforcer(self)
        e.add_dsd_constraint({"requester", "approver"}, 1)

        # Two coexisting sessions for the same user may activate conflicting
        # roles; the DSD constraint is evaluated per session.
        session1 = e.create_session("alice", "dom1")
        session2 = e.create_session("alice", "dom1")
        session1.activate_role("requester")
        session2.activate_role("approver")

        self.assertTrue(e.enforce_with_session(session1, "alice", "dom1", "requisition", "create"))
        self.assertFalse(e.enforce_with_session(session1, "alice", "dom1", "requisition", "approve"))
        self.assertFalse(e.enforce_with_session(session2, "alice", "dom1", "requisition", "create"))
        self.assertTrue(e.enforce_with_session(session2, "alice", "dom1", "requisition", "approve"))

    def test_cross_domain_same_name_roles(self):
        e = get_procurement_enforcer(self)

        session_dom1 = e.create_session("alice", "dom1")
        session_dom2 = e.create_session("alice", "dom2")
        session_dom1.activate_role("approver")
        session_dom2.activate_role("approver")

        # The same-named approver role grants different permissions per domain.
        self.assertTrue(e.enforce_with_session(session_dom1, "alice", "dom1", "requisition", "approve"))
        self.assertFalse(e.enforce_with_session(session_dom1, "alice", "dom1", "budget", "approve"))
        self.assertTrue(e.enforce_with_session(session_dom2, "alice", "dom2", "budget", "approve"))
        self.assertFalse(e.enforce_with_session(session_dom2, "alice", "dom2", "requisition", "approve"))

    def test_revoked_assignment_stops_working_in_session(self):
        e = get_procurement_enforcer(self)
        session = e.create_session("alice", "dom1")
        session.activate_role("approver")
        self.assertTrue(e.enforce_with_session(session, "alice", "dom1", "requisition", "approve"))

        # After the assignment is revoked, the old activation state must not
        # keep granting permissions.
        e.delete_roles_for_user_in_domain("alice", "approver", "dom1")
        self.assertFalse(e.enforce_with_session(session, "alice", "dom1", "requisition", "approve"))

        # Re-activating the revoked role fails at activation time.
        with self.assertRaises(casbin.SessionError):
            session.activate_role("approver")

    def test_closed_session_cannot_enforce(self):
        e = get_procurement_enforcer(self)
        session = e.create_session("alice", "dom1")
        session.activate_role("requester")

        self.assertTrue(e.close_session(session))
        self.assertFalse(session.is_open)
        self.assertIsNone(e.get_session(session.id))

        with self.assertRaises(casbin.SessionError):
            e.enforce_with_session(session, "alice", "dom1", "requisition", "create")
        with self.assertRaises(casbin.SessionError):
            session.activate_role("approver")

    def test_session_does_not_affect_session_less_enforce(self):
        e = get_procurement_enforcer(self)
        e.add_dsd_constraint({"requester", "approver"}, 1)

        session = e.create_session("alice", "dom1")
        session.activate_role("requester")

        # Plain enforce() ignores sessions and DSD constraints entirely.
        self.assertTrue(e.enforce("alice", "dom1", "requisition", "create"))
        self.assertTrue(e.enforce("alice", "dom1", "requisition", "approve"))
        self.assertTrue(e.enforce("bob", "dom1", "requisition", "approve"))

    def test_invalid_dsd_constraint(self):
        e = get_procurement_enforcer(self)
        with self.assertRaises(ValueError):
            e.add_dsd_constraint({"requester"}, 1)
        with self.assertRaises(ValueError):
            e.add_dsd_constraint({"requester", "approver"}, 0)
        with self.assertRaises(ValueError):
            e.add_dsd_constraint({"requester", "approver"}, 2)
