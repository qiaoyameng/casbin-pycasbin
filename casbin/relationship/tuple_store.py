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

"""In-memory relationship tuple storage.

A tuple relates ``object type:id#relation`` to a subject, where the subject
is a direct user, an object or a userset reference.  Only caller-provided
data is held; there is no external permission service.
"""

from .entities import User, ObjectRef, UsersetRef, parse_subject
from .errors import InvalidTupleError


class RelationshipTuple:
    """``(object_type, object_id, relation) -> subject``."""

    __slots__ = ("object_type", "object_id", "relation", "subject")

    def __init__(self, object_type, object_id, relation, subject):
        if not isinstance(object_type, str) or object_type == "":
            raise InvalidTupleError("object_type must be a non-empty string")
        if not isinstance(object_id, str) or object_id == "":
            raise InvalidTupleError("object_id must be a non-empty string")
        if not isinstance(relation, str) or relation == "":
            raise InvalidTupleError("relation must be a non-empty string")
        self.object_type = object_type
        self.object_id = object_id
        self.relation = relation
        self.subject = parse_subject(subject)

    @property
    def key(self):
        return self.object_type, self.object_id, self.relation

    @staticmethod
    def parse(text):
        """Parse ``"type:id#relation@subject"`` where subject is itself a
        ``type:id#relation``, ``type:id`` or plain user string."""
        if not isinstance(text, str) or "@" not in text:
            raise InvalidTupleError(
                "tuple string must look like 'type:id#relation@subject'"
            )
        object_part, _, subject_part = text.partition("@")
        if "#" not in object_part:
            raise InvalidTupleError("tuple object part must contain a '#relation'")
        head, _, relation = object_part.partition("#")
        if ":" not in head:
            raise InvalidTupleError("tuple object part must contain a 'type:id'")
        type, _, id = head.partition(":")
        return RelationshipTuple(type, id, relation, subject_part)

    def __eq__(self, other):
        return (
            isinstance(other, RelationshipTuple)
            and other.key == self.key
            and other.subject == self.subject
        )

    def __hash__(self):
        return hash((self.key, self.subject))

    def __repr__(self):
        return "RelationshipTuple(%r, %r, %r, %r)" % (
            self.object_type,
            self.object_id,
            self.relation,
            self.subject,
        )


class TupleStore:
    """A set of relationship tuples kept purely in memory."""

    def __init__(self, tuples=()):
        self._tuples = set()
        self._version = 0
        for tuple_item in tuples:
            self.add(tuple_item)

    @property
    def version(self):
        """Monotonically increasing change counter (cache invalidation)."""
        return self._version

    def _coerce(self, tuple_or_text, *args):
        if isinstance(tuple_or_text, RelationshipTuple):
            return tuple_or_text
        if args:
            return RelationshipTuple(tuple_or_text, args[0], args[1], args[2])
        return RelationshipTuple.parse(tuple_or_text)

    def add(self, tuple_or_text, *args):
        tuple_item = self._coerce(tuple_or_text, *args)
        if tuple_item not in self._tuples:
            self._tuples.add(tuple_item)
            self._version += 1
        return tuple_item

    def remove(self, tuple_or_text, *args):
        tuple_item = self._coerce(tuple_or_text, *args)
        if tuple_item not in self._tuples:
            raise InvalidTupleError("tuple not found: %r" % (tuple_item,))
        self._tuples.remove(tuple_item)
        self._version += 1

    def clear(self):
        if self._tuples:
            self._tuples.clear()
            self._version += 1

    def subjects(self, object_type, object_id, relation):
        """All subjects written directly on ``type:id#relation``."""
        return [t.subject for t in self._tuples if t.key == (object_type, object_id, relation)]

    def object_subjects(self, object_type, object_id, relation):
        """Object/userset subjects on ``type:id#relation`` (no direct users)."""
        result = []
        for subject in self.subjects(object_type, object_id, relation):
            if isinstance(subject, (ObjectRef, UsersetRef)):
                result.append(subject)
        return result

    def all(self):
        return set(self._tuples)

    def __len__(self):
        return len(self._tuples)

    def __contains__(self, tuple_item):
        return tuple_item in self._tuples
