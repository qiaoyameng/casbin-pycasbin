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

import itertools


class SessionError(RuntimeError):
    """raised when a session operation is not allowed,
    e.g. activating a role the user does not own or
    violating a dynamic separation-of-duty constraint.
    """


class Session:
    """Session represents an activated-role context for one user.

    A session is bound to a user and (optionally) a domain. Roles activated
    in the session are the only starting points of the `g` relation when
    enforcing with this session. Sessions are independent of each other.
    """

    def __init__(self, session_id, user, domain=None):
        self.id = session_id
        self.user = user
        self.domain = domain
        self.activated_roles = set()

    def __repr__(self):
        return "Session(id={!r}, user={!r}, domain={!r}, activated_roles={!r})".format(
            self.id, self.user, self.domain, sorted(self.activated_roles)
        )


class RoleActivationConstraint:
    """RoleActivationConstraint is a dynamic separation-of-duty (DSD) rule:
    within one session, at most `max_active` roles that belong to (or inherit
    any member of) `roles` may be activated at the same time.
    """

    _id_counter = itertools.count(1)

    def __init__(self, roles, max_active):
        roles = set(roles)
        if not roles:
            raise ValueError("a DSD constraint needs at least one role")
        if max_active < 1:
            raise ValueError("max_active must be >= 1")
        self.id = next(self._id_counter)
        self.roles = roles
        self.max_active = max_active

    def __repr__(self):
        return "RoleActivationConstraint(id={!r}, roles={!r}, max_active={!r})".format(
            self.id, sorted(self.roles), self.max_active
        )
