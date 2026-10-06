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

"""RelationshipStore: the single entry point for relationship tuples.

It combines a static :class:`~casbin.relationship.schema.Schema`, an
in-memory :class:`~casbin.relationship.tuple_store.TupleStore` and the
fixpoint :class:`~casbin.relationship.evaluator.UsersetEvaluator`.
"""

from .errors import UndefinedRelationError
from .evaluator import UsersetEvaluator
from .schema import Schema
from .tuple_store import TupleStore, RelationshipTuple


class RelationshipStore:
    """Holds caller-provided relationship tuples in memory and answers
    userset / membership questions."""

    def __init__(self, schema, tuples=()):
        if not isinstance(schema, Schema):
            schema = Schema(schema)
        self.schema = schema
        self.tuples = tuples if isinstance(tuples, TupleStore) else TupleStore(tuples)
        self._evaluator = UsersetEvaluator(self.schema, self.tuples)

    # -- tuple management -------------------------------------------------

    def add_tuple(self, object_type=None, object_id=None, relation=None, subject=None, *, tuple=None):
        """Add a relationship tuple.

        Accepts either positional fields
        ``add_tuple("document", "1", "viewer", "alice")`` or a Zanzibar-style
        string ``add_tuple("document:1#viewer@alice")`` or a
        :class:`RelationshipTuple`.
        """
        if tuple is not None:
            item = self.tuples.add(tuple)
        elif object_id is None and relation is None and subject is None:
            item = self.tuples.add(object_type)
        else:
            item = self.tuples.add(object_type, object_id, relation, subject)
        self._check_tuple_relation(item)
        return item

    def remove_tuple(self, object_type=None, object_id=None, relation=None, subject=None, *, tuple=None):
        if tuple is not None:
            self.tuples.remove(tuple)
        elif object_id is None and relation is None and subject is None:
            self.tuples.remove(object_type)
        else:
            self.tuples.remove(object_type, object_id, relation, subject)

    def clear_tuples(self):
        self.tuples.clear()

    def _check_tuple_relation(self, item):
        if not self.schema.has(item.object_type, item.relation):
            raise UndefinedRelationError(
                "tuple uses relation %s#%s which is not in the schema"
                % (item.object_type, item.relation)
            )

    # -- authorization ----------------------------------------------------

    def userset(self, object_type, object_id, relation):
        """All users that belong to ``type:id#relation`` (least fixpoint)."""
        return self._evaluator.userset(object_type, object_id, relation)

    def check(self, user, object_type, object_id, relation):
        """Whether ``user`` belongs to ``type:id#relation``."""
        return self._evaluator.check(user, object_type, object_id, relation)
