"""In-memory relation tuple store.

Only tuples explicitly supplied by the caller are held here; there is no
external permission service or network lookup.
"""

from dataclasses import dataclass

from .entities import Entity, entity, subject as parse_subject


@dataclass(frozen=True)
class RelationTuple:
    """One ``<object>#<relation>@<subject>`` relation tuple."""

    object: Entity
    relation: str
    subject: object  # entities.Subject

    @property
    def key(self):
        return str(self.object), self.relation

    def __str__(self):
        return f"{self.object}#{self.relation}@{self.subject}"


def tuple_from_string(text):
    """Parse ``"document:plan.pdf#viewer@user:alice"`` into a RelationTuple."""

    if "#" not in text or "@" not in text:
        raise ValueError(f"invalid relation tuple {text!r}, expected 'object#relation@subject'")
    obj_part, rest = text.split("#", 1)
    rel_part, subj_part = rest.split("@", 1)
    if not obj_part or not rel_part or not subj_part:
        raise ValueError(f"invalid relation tuple {text!r}")
    return RelationTuple(entity(obj_part), rel_part, parse_subject(subj_part))


def _normalize_tuple(value):
    if isinstance(value, RelationTuple):
        return value
    if isinstance(value, str):
        return tuple_from_string(value)
    raise TypeError(f"unsupported tuple value: {type(value)!r}")


class TupleStore:
    """Holds the caller's in-memory relation tuples."""

    def __init__(self, tuples=(), model=None):
        self._tuples = set()
        self._version = 0
        self.model = model
        for value in tuples:
            self.add(value)

    @property
    def version(self):
        return self._version

    def add(self, value):
        rel_tuple = _normalize_tuple(value)
        if self.model is not None:
            self.model.validate_tuple(rel_tuple.object, rel_tuple.relation, rel_tuple.subject)
        if rel_tuple in self._tuples:
            return False
        self._tuples.add(rel_tuple)
        self._version += 1
        return True

    def remove(self, value):
        rel_tuple = _normalize_tuple(value)
        if rel_tuple not in self._tuples:
            return False
        self._tuples.remove(rel_tuple)
        self._version += 1
        return True

    def clear(self):
        if self._tuples:
            self._tuples.clear()
            self._version += 1

    def __len__(self):
        return len(self._tuples)

    def __iter__(self):
        return iter(self._tuples)

    def __contains__(self, value):
        return _normalize_tuple(value) in self._tuples

    def for_relation(self, obj, relation):
        """Raw tuple subjects written directly on ``obj#relation``."""

        obj_key = str(obj)
        return [rel_tuple.subject for rel_tuple in self._tuples
                if rel_tuple.relation == relation and str(rel_tuple.object) == obj_key]

    def snapshot(self):
        return frozenset(self._tuples)
