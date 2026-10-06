"""Fixed-point evaluation of relation membership over finite in-memory data.

Evaluation follows the dependency graph's strongly connected components in
bottom-up order. A component is stratified away from all negation (guaranteed
by :meth:`RelationModel._reject_negative_recursion`), so within a component the
operators are monotone and Jacobi iteration from the empty set converges to the
least fixed point on the finite data universe.
"""

from collections import defaultdict

from .entities import Relation, User
from .model import (
    ComputedUserset,
    Difference,
    Intersection,
    This,
    TupleToUserset,
    Union,
)
from .store import TupleStore



class RelationChecker:
    """Answers membership questions against a model and a TupleStore."""

    def __init__(self, model, store):
        self.model = model
        self.store = store
        self._tables = {}
        self._tables_version = None

    def check(self, who, obj, relation):
        """True if user ``who`` is a member of ``obj#relation``."""

        member = who if isinstance(who, User) else User(_as_user_id(who))
        if isinstance(obj, str):
            obj = _entity_from_string(obj)
        relation = _relation_name(relation)
        tables = self._ensure_tables()
        return member.id in tables.get((obj.type_name, relation), {}).get(str(obj), frozenset())

    def userset_members(self, obj, relation):
        """All users in ``obj#relation`` under the fixed-point semantics."""

        if isinstance(obj, str):
            obj = _entity_from_string(obj)
        relation = _relation_name(relation)
        self.model.require(obj.type_name, relation)
        tables = self._ensure_tables()
        by_object = tables[(obj.type_name, relation)]
        return frozenset(User(uid) for uid in by_object.get(str(obj), frozenset()))

    def relations_on(self, who, obj):
        """Relations of ``obj`` that ``who`` is a member of."""

        tables = self._ensure_tables()
        if isinstance(obj, str):
            obj = _entity_from_string(obj)
        member = who if isinstance(who, User) else User(_as_user_id(who))
        result = set()
        for (type_name, relation), by_object in tables.items():
            if type_name == obj.type_name and member.id in by_object.get(str(obj), frozenset()):
                result.add(relation)
        return result

    def _ensure_tables(self):
        if self._tables_version != self.store.version:
            self._tables = self._compute_tables()
            self._tables_version = self.store.version
        return self._tables

    def _compute_tables(self):
        tuples = list(self.store)
        entities, all_users = _universe(tuples)
        ordered = _component_order(self.model.dependencies)

        tables = {key: defaultdict(set) for key in self.model.specs}
        direct_users = defaultdict(set)
        for rel_tuple in tuples:
            key = (rel_tuple.object.type_name, rel_tuple.relation)
            object_key = str(rel_tuple.object)
            if rel_tuple.subject.is_direct_user:
                direct_users[(key, object_key)].add(rel_tuple.subject.user.id)

        for component in ordered:
            self._compute_component(component, tables, direct_users, entities, all_users)

        return {key: {obj: frozenset(members) for obj, members in by_object.items()}
                for key, by_object in tables.items()}

    def _compute_component(self, component, tables, direct_users, entities, all_users):
        members = set(component)
        changed = True
        iterations = 0
        # Jacobi is monotone: each sweep that does not converge adds at least
        # one (object, user) cell, so this is a strict upper bound on sweeps.
        total_cells = sum(len(entities.get(type_name, ())) for type_name, _ in component) * max(1, len(all_users))
        limit = total_cells + 1
        while changed:
            changed = False
            iterations += 1
            if iterations > limit:
                raise RuntimeError("relation fixed point did not converge")
            for key in component:
                type_name, relation = key
                current = tables[key]
                updated = defaultdict(set)
                entity_ids = entities.get(type_name, ())
                for object_id in entity_ids:
                    object_key = f"{type_name}:{object_id}"
                    value = self._expand(
                        self.model.require(type_name, relation).rewrite,
                        type_name, object_id, object_key,
                        tables, members, direct_users, relation,
                    )
                    if value != current.get(object_key, frozenset()):
                        changed = True
                    if value:
                        updated[object_key] = value
                tables[key] = updated

    def _expand(self, node, type_name, object_id, object_key, tables, active, direct_users, relation):
        if isinstance(node, This):
            return set(direct_users.get(((type_name, relation), object_key), set()))
        if isinstance(node, ComputedUserset):
            return self._read(tables, active, (type_name, node.relation), object_key)
        if isinstance(node, TupleToUserset):
            return self._expand_ttu(node, type_name, object_key, tables, active)
        if isinstance(node, Union):
            result = set()
            for branch in node.branches:
                result |= self._expand(branch, type_name, object_id, object_key, tables, active, direct_users, relation)
            return result
        if isinstance(node, Intersection):
            result = None
            for branch in node.branches:
                part = self._expand(branch, type_name, object_id, object_key, tables, active, direct_users, relation)
                result = part if result is None else result & part
            return result if result is not None else set()
        if isinstance(node, Difference):
            base = self._expand(node.base, type_name, object_id, object_key, tables, active, direct_users, relation)
            subtract = self._expand(node.subtract, type_name, object_id, object_key, tables, active, direct_users, relation)
            return base - subtract
        raise TypeError(f"unsupported rewrite node {type(node)!r}")

    def _read(self, tables, active, key, object_key):
        if key in active:
            return set(tables[key].get(object_key, set()))
        return set(tables[key].get(object_key, frozenset()))

    def _expand_ttu(self, node, type_name, object_key, tables, active):
        result = set()
        for rel_tuple in self.store:
            if rel_tuple.object.type_name != type_name or str(rel_tuple.object) != object_key:
                continue
            if rel_tuple.relation != node.tupleset:
                continue
            subj = rel_tuple.subject
            if subj.userset is not None:
                target = str(subj.userset.object)
                target_relation = subj.userset.relation.name
                if target_relation != node.computed_relation:
                    continue
            elif subj.is_bare_object:
                target = str(subj.object)
                target_relation = node.computed_relation
            else:
                continue
            target_type = target.split(":", 1)[0]
            result |= self._read(tables, active, (target_type, target_relation), target)
        return result




def _universe(tuples):
    entities = defaultdict(set)
    users = set()
    for rel_tuple in tuples:
        entities[rel_tuple.object.type_name].add(rel_tuple.object.id)
        subj = rel_tuple.subject
        if subj.is_direct_user:
            users.add(subj.user.id)
        elif subj.userset is not None:
            entities[subj.userset.object.type_name].add(subj.userset.object.id)
        elif subj.is_bare_object:
            entities[subj.object.type_name].add(subj.object.id)
    return {type_name: sorted(ids) for type_name, ids in entities.items()}, users


def _component_order(dependencies):
    """Tarjan SCCs, returned in bottom-up dependency order (dependencies first)."""

    index_counter = [0]
    stack = []
    on_stack = set()
    indices = {}
    lowlink = {}
    components = []

    def strongconnect(node):
        indices[node] = index_counter[0]
        lowlink[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        on_stack.add(node)
        for target in dependencies.get(node, {}):
            if target not in indices:
                strongconnect(target)
                lowlink[node] = min(lowlink[node], lowlink[target])
            elif target in on_stack:
                lowlink[node] = min(lowlink[node], indices[target])
        if lowlink[node] == indices[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == node:
                    break
            components.append(component)

    for node in dependencies:
        if node not in indices:
            strongconnect(node)
    return components


def _as_user_id(who):
    from .entities import user
    return user(who).id


def _relation_name(relation):
    return relation.name if isinstance(relation, Relation) else relation


def _entity_from_string(ref):
    from .entities import entity
    return entity(ref)
