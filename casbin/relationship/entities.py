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

"""Typed subjects and userset rewrite expressions.

The model keeps three concepts strictly separate:

* :class:`User`        -- a concrete user identity;
* :class:`ObjectRef`   -- an object itself (``type:id``), the subject of a
                          ``...#member`` style tuple;
* :class:`UsersetRef`  -- a relation on another object (``type:id#relation``),
                          i.e. a userset that must be followed.
"""

from .errors import InvalidSubjectError


def _valid_name(value, kind):
    if not isinstance(value, str) or value == "":
        raise InvalidSubjectError("%s must be a non-empty string" % kind)
    if value.startswith(" ") or value.endswith(" "):
        raise InvalidSubjectError("%s must not contain surrounding whitespace" % kind)
    return value


class User:
    """A concrete user identity (a subject that cannot be expanded)."""

    __slots__ = ("id",)

    def __init__(self, id):
        self.id = _valid_name(id, "user id")

    def __eq__(self, other):
        return isinstance(other, User) and self.id == other.id

    def __hash__(self):
        return hash(("User", self.id))

    def __repr__(self):
        return "User(%r)" % self.id

    def __str__(self):
        return self.id


class ObjectRef:
    """Reference to an object itself, written ``type:id``.

    As a tuple subject it means "the userset of this object's ``member``
    relation"; the concrete relation is supplied by the rewrite.
    """

    __slots__ = ("type", "id")

    def __init__(self, type, id):
        self.type = _valid_name(type, "object type")
        self.id = _valid_name(id, "object id")

    def userset(self, relation):
        return UsersetRef(self.type, self.id, relation)

    def __eq__(self, other):
        return (
            isinstance(other, ObjectRef)
            and self.type == other.type
            and self.id == other.id
        )

    def __hash__(self):
        return hash(("ObjectRef", self.type, self.id))

    def __repr__(self):
        return "ObjectRef(%r, %r)" % (self.type, self.id)

    def __str__(self):
        return "%s:%s" % (self.type, self.id)


class UsersetRef:
    """Reference to a relation on an object, written ``type:id#relation``."""

    __slots__ = ("type", "id", "relation")

    def __init__(self, type, id, relation):
        self.type = _valid_name(type, "object type")
        self.id = _valid_name(id, "object id")
        self.relation = _valid_name(relation, "relation name")

    @property
    def object(self):
        return ObjectRef(self.type, self.id)

    def __eq__(self, other):
        return (
            isinstance(other, UsersetRef)
            and self.type == other.type
            and self.id == other.id
            and self.relation == other.relation
        )

    def __hash__(self):
        return hash(("UsersetRef", self.type, self.id, self.relation))

    def __repr__(self):
        return "UsersetRef(%r, %r, %r)" % (self.type, self.id, self.relation)

    def __str__(self):
        return "%s:%s#%s" % (self.type, self.id, self.relation)


def parse_subject(value):
    """Parse a tuple subject.

    ``"type:id#relation"`` becomes a :class:`UsersetRef`, ``"type:id"`` an
    :class:`ObjectRef`, and anything without ``:`` a :class:`User`.
    ``User``/``ObjectRef``/``UsersetRef`` instances pass through unchanged.
    """
    if isinstance(value, (User, ObjectRef, UsersetRef)):
        return value
    if not isinstance(value, str) or value == "":
        raise InvalidSubjectError("subject must be a non-empty string or a typed subject")

    fragment = value.split("#", 1)
    head = fragment[0]
    if ":" not in head:
        # No object type separator: this is a plain user identity.
        return User(value)
    type, _, id = head.partition(":")
    if type == "" or id == "" or id.endswith(":"):
        raise InvalidSubjectError("invalid object reference %r, expected type:id" % value)
    if len(fragment) == 2:
        if fragment[1] == "":
            raise InvalidSubjectError("invalid userset reference %r: empty relation" % value)
        return UsersetRef(type, id, fragment[1])
    return ObjectRef(type, id)


# ---------------------------------------------------------------------------
# Userset rewrite nodes
# ---------------------------------------------------------------------------


class Node:
    """Base class of a userset rewrite expression node."""

    def union(self, *others):
        children = [self]
        for other in others:
            children.extend(other.children if isinstance(other, Union) else [other])
        return Union(children)

    def intersect(self, *others):
        children = [self]
        for other in others:
            children.extend(other.children if isinstance(other, Intersect) else [other])
        return Intersect(children)

    def subtract(self, *others):
        return Difference(self, list(others))

    def __or__(self, other):
        return self.union(other)

    def __and__(self, other):
        return self.intersect(other)

    def __sub__(self, other):
        return self.subtract(other)


class _This(Node):
    """Direct members stored under the current object#relation.

    Tuple subjects that are themselves objects are expanded through
    ``member`` (or an explicitly given relation).
    """

    def __init__(self, via="member"):
        self.via = _valid_name(via, "member relation")

    def __eq__(self, other):
        return isinstance(other, _This) and other.via == self.via

    def __hash__(self):
        return hash(("_This", self.via))

    def __repr__(self):
        return "direct(%r)" % self.via if self.via != "member" else "direct()"


class _TupleToUserset(Node):
    """For every object O in ``this#tuple_relation``, take ``O#computed_relation``.

    This is the "point to a relation on another object" step (folders,
    parents, teams): the related object id is read from a tuple of the
    current object, and a fixed relation on that object contributes its
    userset.
    """

    def __init__(self, tuple_relation, computed_relation):
        self.tuple_relation = _valid_name(tuple_relation, "tuple relation")
        self.computed_relation = _valid_name(computed_relation, "computed relation")

    def __eq__(self, other):
        return (
            isinstance(other, _TupleToUserset)
            and other.tuple_relation == self.tuple_relation
            and other.computed_relation == self.computed_relation
        )

    def __hash__(self):
        return hash(("_TupleToUserset", self.tuple_relation, self.computed_relation))

    def __repr__(self):
        return "tuple_userset(%r, %r)" % (self.tuple_relation, self.computed_relation)


class _ComputedUserset(Node):
    """Another relation of the same object (``object#relation``)."""

    def __init__(self, relation):
        self.relation = _valid_name(relation, "relation")

    def __eq__(self, other):
        return isinstance(other, _ComputedUserset) and other.relation == self.relation

    def __hash__(self):
        return hash(("_ComputedUserset", self.relation))

    def __repr__(self):
        return "computed(%r)" % self.relation


class Union(Node):
    """Union of child usersets."""

    def __init__(self, children):
        children = list(children)
        if len(children) < 2:
            raise ValueError("Union requires at least two children")
        self.children = children

    def __eq__(self, other):
        return isinstance(other, Union) and other.children == self.children

    def __hash__(self):
        return hash(("Union", tuple(self.children)))

    def __repr__(self):
        return "union([%s])" % ", ".join(repr(c) for c in self.children)


class Intersect(Node):
    """Intersection of child usersets."""

    def __init__(self, children):
        children = list(children)
        if len(children) < 2:
            raise ValueError("Intersect requires at least two children")
        self.children = children

    def __eq__(self, other):
        return isinstance(other, Intersect) and other.children == self.children

    def __hash__(self):
        return hash(("Intersect", tuple(self.children)))

    def __repr__(self):
        return "intersect([%s])" % ", ".join(repr(c) for c in self.children)


class Difference(Node):
    """Base userset with one or more usersets removed."""

    def __init__(self, base, subtracted):
        subtracted = list(subtracted)
        if not subtracted:
            raise ValueError("Difference requires at least one subtracted userset")
        self.base = base
        self.subtracted = subtracted

    def __eq__(self, other):
        return (
            isinstance(other, Difference)
            and other.base == self.base
            and other.subtracted == self.subtracted
        )

    def __hash__(self):
        return hash(("Difference", self.base, tuple(self.subtracted)))

    def __repr__(self):
        return "difference(%r, %r)" % (self.base, self.subtracted)


# Public constructors.
def direct(via="member"):
    return _This(via)


def tuple_userset(tuple_relation, computed_relation):
    return _TupleToUserset(tuple_relation, computed_relation)


def computed(relation):
    return _ComputedUserset(relation)


def union(children):
    return Union(children)


def intersect(children):
    return Intersect(children)


def difference(base, subtracted):
    return Difference(base, list(subtracted) if isinstance(subtracted, (list, tuple)) else [subtracted])
