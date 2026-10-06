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


class SessionError(RuntimeError):
    """raised when a session operation is not allowed,
    e.g. activating a role the user does not own, violating a dynamic
    separation-of-duty constraint, or using a closed session."""


class DSDConstraint:
    """DSDConstraint is a dynamic separation-of-duty constraint:
    within a single session, at most max_active roles out of roles may be
    activated. Role inheritance is taken into account, so activating a role
    that inherits a constrained role counts as activating the constrained
    role itself."""

    def __init__(self, roles, max_active):
        roles = frozenset(roles)
        if len(roles) < 2:
            raise ValueError("a DSD constraint needs at least two roles")
        if max_active < 1:
            raise ValueError("max_active must be at least 1")
        if max_active >= len(roles):
            raise ValueError("max_active must be smaller than the number of constrained roles")

        self.roles = roles
        self.max_active = max_active

    def __repr__(self):
        return "DSDConstraint(roles={}, max_active={})".format(sorted(self.roles), self.max_active)


class Session:
    """Session is a per-user, per-domain role activation context.

    A session starts with no activated roles. Roles are activated explicitly
    with activate_role(); only roles the user actually owns in the session's
    domain can be activated. Enforcing through the session (see
    Enforcer.enforce_with_session) resolves the user's roles from the
    activated set only, so a user holding several positions never exercises
    more than the activated ones within one session. Sessions are independent
    of each other and never affect session-less enforce().
    """

    def __init__(self, enforcer, session_id, user, domain=None):
        self._enforcer = enforcer
        self.id = session_id
        self.user = user
        self.domain = str(domain) if domain is not None else None
        self._activated_roles = []
        self._is_open = True

    @property
    def is_open(self):
        """returns true while the session has not been closed."""
        return self._is_open

    def activate_role(self, role):
        """activates role for this session.

        Raises SessionError if the session is closed, if the user does not
        own the role in the session's domain, or if the activation would
        violate a dynamic separation-of-duty constraint.
        """
        self._enforcer._activate_role(self, role)

    def deactivate_role(self, role):
        """removes role from this session's activated set."""
        self._enforcer._deactivate_role(self, role)

    def get_activated_roles(self):
        """returns the roles currently activated in this session."""
        return list(self._activated_roles)

    def close(self):
        """closes the session; it can no longer be used for enforcement."""
        self._enforcer.close_session(self)

    def __repr__(self):
        return "Session(id={!r}, user={!r}, domain={!r}, activated={!r})".format(
            self.id, self.user, self.domain, self._activated_roles
        )
