# Copyright 2024 The casbin Authors. All Rights Reserved.
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

"""Casbin enforcer integration for relationship tuples.

``RelationshipEnforcer`` is a standard Casbin :class:`~casbin.Enforcer`
whose matcher delegates membership checks to a
:class:`~casbin.relationship.store.RelationshipStore`.  Calls go through
the normal ``enforce`` path; only in-memory tuples provided by the caller
are consulted.
"""

from .schema import Schema
from .store import RelationshipStore

_RELATION_MODEL = """
[request_definition]
r = sub, obj_type, obj_id, relation

[policy_definition]
p = _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = checkRelation(r.sub, r.obj_type, r.obj_id, r.relation)
"""


class RelationshipEnforcer:
    """Casbin enforcer backed by relationship tuples.

    ``enforce(user, object_type, object_id, relation)`` returns whether the
    user belongs to the object's relation userset.  The underlying plain
    Casbin enforcer is available as ``self.enforcer``.
    """

    def __init__(self, schema=None, tuples=(), store=None, enable_log=False):
        if store is not None:
            self.store = store
        else:
            self.store = RelationshipStore(schema if schema is not None else Schema({}), tuples)

        from casbin import Enforcer
        from casbin.model import Model

        model = Model()
        model.load_model_from_text(_RELATION_MODEL)
        self.enforcer = Enforcer(model, enable_log=enable_log)
        # The matcher is evaluated per request, so a single placeholder
        # policy row is enough to drive the normal matching/effect path.
        self.enforcer.add_policy("placeholder")
        self.enforcer.add_function("checkRelation", self._check_relation)

    def _check_relation(self, user, object_type, object_id, relation):
        return self.store.check(user, object_type, object_id, relation)

    # -- standard Casbin entry point -------------------------------------

    def enforce(self, user, object_type=None, object_id=None, relation=None):
        """Check ``user`` against ``type:id#relation``.

        Also accepts a single combined object argument:
        ``enforce("alice", "document:1#viewer")``.
        """
        if object_id is None and relation is None and isinstance(object_type, str) and "#" in object_type:
            head, _, relation = object_type.partition("#")
            type_name, _, object_id = head.partition(":")
            object_type = type_name
        return self.enforcer.enforce(user, object_type, object_id, relation)

    def enforce_ex(self, user, object_type, object_id, relation):
        return self.enforcer.enforce_ex(user, object_type, object_id, relation)

    # -- tuple delegation -------------------------------------------------

    def add_tuple(self, *args, **kwargs):
        return self.store.add_tuple(*args, **kwargs)

    def remove_tuple(self, *args, **kwargs):
        return self.store.remove_tuple(*args, **kwargs)

    def clear_tuples(self):
        self.store.clear_tuples()

    def userset(self, object_type, object_id, relation):
        return self.store.userset(object_type, object_id, relation)

    def check(self, user, object_type, object_id, relation):
        return self.store.check(user, object_type, object_id, relation)
