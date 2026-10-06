"""Zanzibar-style relation tuple authorization for Casbin (in-memory only)."""

from .entities import (
    Entity,
    ObjectType,
    Relation,
    User,
    UsersetRef,
    Subject,
    entity,
    subject,
    user,
    USER_TYPE,
)
from .model import (
    AllowedSubject,
    ComputedUserset,
    Difference,
    Intersection,
    Node,
    RelationModel,
    RelationModelError,
    RelationSpec,
    SubjectKind,
    This,
    TupleToUserset,
    Union,
    direct_users,
    object_of,
    userset_of,
)
from .store import RelationTuple, TupleStore, tuple_from_string
from .checker import RelationChecker
from .enforcer import RelationEnforcer, new_relation_enforcer, DEFAULT_ACTION_RELATIONS

__all__ = [
    "Entity", "ObjectType", "Relation", "User", "UsersetRef", "Subject",
    "entity", "subject", "user", "USER_TYPE",
    "AllowedSubject", "ComputedUserset", "Difference", "Intersection", "Node",
    "RelationModel", "RelationModelError", "RelationSpec", "SubjectKind",
    "This", "TupleToUserset", "Union",
    "direct_users", "object_of", "userset_of",
    "RelationTuple", "TupleStore", "tuple_from_string",
    "RelationChecker",
    "RelationEnforcer", "new_relation_enforcer", "DEFAULT_ACTION_RELATIONS",
]
