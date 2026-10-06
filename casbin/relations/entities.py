"""Typed identities for relation tuple based authorization.

The three concepts that must never be confused are kept as distinct types:

* ``ObjectType``: namespace/kind of a resource ("document", "folder", ...).
* ``Relation``:  name of a relation on a type ("viewer", "parent", ...).
* ``User`` / ``Entity``: concrete actors vs concrete resource objects.
"""

from dataclasses import dataclass

USER_TYPE = "user"
_NAMESPACE_SEP = ":"


@dataclass(frozen=True)
class ObjectType:
    """The type (namespace) of an object, e.g. ``document``."""

    name: str

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name:
            raise TypeError("object type name must be a non-empty string")

    def __str__(self):
        return self.name


@dataclass(frozen=True)
class Relation:
    """The name of a relation defined on an object type, e.g. ``viewer``."""

    name: str

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name:
            raise TypeError("relation name must be a non-empty string")

    def __str__(self):
        return self.name


@dataclass(frozen=True)
class Entity:
    """A concrete object instance, identified by type and id: ``document:plan.pdf``."""

    type: ObjectType
    id: str

    def __post_init__(self):
        if not isinstance(self.type, ObjectType):
            raise TypeError("entity type must be an ObjectType")
        if not isinstance(self.id, str) or not self.id:
            raise TypeError("entity id must be a non-empty string")

    @property
    def type_name(self):
        return self.type.name

    def __str__(self):
        return f"{self.type.name}{_NAMESPACE_SEP}{self.id}"


def entity(ref):
    """Build an :class:`Entity` from an Entity or a ``"type:id"`` string."""

    if isinstance(ref, Entity):
        return ref
    if not isinstance(ref, str):
        raise TypeError(f"expected Entity or 'type:id' string, got {type(ref)!r}")
    parts = ref.split(_NAMESPACE_SEP, 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"invalid object reference {ref!r}, expected 'type:id'")
    return Entity(ObjectType(parts[0]), parts[1])


@dataclass(frozen=True)
class User:
    """A concrete user identity, always rendered as ``user:<id>``."""

    id: str

    def __post_init__(self):
        if not isinstance(self.id, str) or not self.id:
            raise TypeError("user id must be a non-empty string")

    @property
    def entity(self):
        return Entity(ObjectType(USER_TYPE), self.id)

    def __str__(self):
        return f"{USER_TYPE}{_NAMESPACE_SEP}{self.id}"


def user(ref):
    """Build a :class:`User` from a User or a string (``"alice"`` or ``"user:alice"``)."""

    if isinstance(ref, User):
        return ref
    if isinstance(ref, Entity):
        if ref.type_name != USER_TYPE:
            raise ValueError(f"entity {ref} is not a user")
        return User(ref.id)
    if not isinstance(ref, str):
        raise TypeError(f"expected User or string, got {type(ref)!r}")
    if _NAMESPACE_SEP in ref:
        ent = entity(ref)
        if ent.type_name != USER_TYPE:
            raise ValueError(f"invalid user reference {ref!r}")
        return User(ent.id)
    return User(ref)


@dataclass(frozen=True)
class UsersetRef:
    """A userset ``<object>#<relation>``, such as ``folder:root#viewer``."""

    object: Entity
    relation: Relation

    def __post_init__(self):
        if not isinstance(self.object, Entity):
            raise TypeError("userset object must be an Entity")
        if not isinstance(self.relation, Relation):
            raise TypeError("userset relation must be a Relation")

    @property
    def key(self):
        return str(self.object), self.relation.name

    def __str__(self):
        return f"{self.object}#{self.relation.name}"


_RELATION_SEP = "#"


@dataclass(frozen=True)
class Subject:
    """The subject of a relation tuple.

    * ``user`` is set for direct member tuples (``...@user:alice``).
    * ``userset`` is set for tuples that point at another object's relation
      (``document:plan.pdf@folder:root#viewer``).
    * ``object`` is set for a bare object reference (``team:eng@team:platform``);
      it grants nothing by itself and only serves tuple-to-userset rewrites.
    """

    user: User = None
    userset: UsersetRef = None
    object: Entity = None

    def __post_init__(self):
        chosen = [v is not None for v in (self.user, self.userset, self.object)]
        if sum(chosen) != 1:
            raise ValueError("subject must be exactly one of user, userset or object")
        if self.user is not None and not isinstance(self.user, User):
            raise TypeError("subject user must be a User")
        if self.userset is not None and not isinstance(self.userset, UsersetRef):
            raise TypeError("subject userset must be a UsersetRef")
        if self.object is not None and not isinstance(self.object, Entity):
            raise TypeError("subject object must be an Entity")

    @property
    def is_direct_user(self):
        return self.user is not None

    @property
    def is_bare_object(self):
        return self.object is not None

    def __str__(self):
        if self.user is not None:
            return str(self.user)
        if self.userset is not None:
            return str(self.userset)
        return str(self.object)


def subject(ref):
    """Parse a subject reference (string or typed value).

    Accepted strings are ``"user:alice"``/``"alice"``, ``"folder:root#viewer"``
    or a bare ``"team:platform"``.
    """

    if isinstance(ref, Subject):
        return ref
    if isinstance(ref, User):
        return Subject(user=ref)
    if isinstance(ref, UsersetRef):
        return Subject(userset=ref)
    if isinstance(ref, Entity):
        return Subject(object=ref)
    if not isinstance(ref, str):
        raise TypeError(f"unsupported subject reference: {type(ref)!r}")
    if _RELATION_SEP in ref:
        obj_part, rel_part = ref.split(_RELATION_SEP, 1)
        if not obj_part or not rel_part:
            raise ValueError(f"invalid userset reference {ref!r}")
        return Subject(userset=UsersetRef(entity(obj_part), Relation(rel_part)))
    if ref.startswith(USER_TYPE + _NAMESPACE_SEP):
        return Subject(user=user(ref))
    return Subject(object=entity(ref))
