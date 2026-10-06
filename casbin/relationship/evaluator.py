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

"""Least-fixpoint evaluation of relationship usersets on finite data.

Semantics
---------
Each ``(object_type, object_id, relation)`` instance denotes the finite set
of users that belong to it.  Its value is defined by the schema rewrite;
references to other usersets (parent objects, teams, sibling relations) are
edges in a finite dependency graph.

* Every set is approximated from below starting from the empty set and
  iterated until it stops growing: the least fixpoint.  Positive recursion
  (folders containing folders, teams containing teams, diamond inheritance)
  is therefore allowed and converges.
* Difference is anti-monotone in its subtracted branch, so a cycle that
  passes through a negative edge has no least-fixpoint meaning.  Such
  cycles are rejected: statically visible ones when the ``Schema`` is built;
  any cycle that data tuples could additionally close is rejected here, as
  an error -- never silently evaluated to ``false``.
"""


from .entities import (
    User,
    ObjectRef,
    UsersetRef,
    _This,
    _TupleToUserset,
    _ComputedUserset,
    Union,
    Intersect,
    Difference,
)
from .errors import InvalidSubjectError, NegativeRecursionError, UndefinedRelationError


class UsersetEvaluator:
    """Computes usersets against a schema and an in-memory tuple store."""

    def __init__(self, schema, store):
        self.schema = schema
        self.store = store

    def check(self, user, object_type, object_id, relation):
        """Return whether ``user`` belongs to ``type:id#relation``."""
        if isinstance(user, User):
            user_id = user.id
        elif isinstance(user, str):
            user_id = user
        else:
            raise InvalidSubjectError("user must be a user id string or User instance")
        return User(user_id) in self.userset(object_type, object_id, relation)

    def userset(self, object_type, object_id, relation):
        """The full set of :class:`User` in ``type:id#relation``."""
        root = self._require_key(object_type, object_id, relation)
        analysis = _InstanceAnalysis(self.schema, self.store)
        analysis.build(root)
        return analysis.solve(root)

    # -- internals --------------------------------------------------------

    def _require_key(self, object_type, object_id, relation):
        if not self.schema.has(object_type, relation):
            raise UndefinedRelationError("unknown relation %s#%s" % (object_type, relation))
        return object_type, object_id, relation


class _InstanceAnalysis:
    """Dependency graph, SCC stratification and fixpoint for one query."""

    def __init__(self, schema, store):
        self.schema = schema
        self.store = store
        # key -> list of (child_key, negative: bool)
        self.edges = {}
        # key -> users contributed directly by a direct() node
        self.direct_users = {}

    # -- graph construction ----------------------------------------------

    def build(self, root):
        pending = [root]
        seen = set()
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            type_name, _, relation = key
            rewrite = self.schema.rewrite(type_name, relation)
            if rewrite is None:
                raise UndefinedRelationError("unknown relation %s#%s" % (type_name, relation))
            children = []
            self._collect(rewrite, key, False, children)
            self.edges[key] = children
            for child, _ in children:
                if child not in seen:
                    pending.append(child)

    def _collect(self, node, key, negative, out):
        type_name, object_id, relation = key
        if isinstance(node, _This):
            users = set()
            for subject in self.store.subjects(type_name, object_id, relation):
                if isinstance(subject, User):
                    users.add(subject)
                elif isinstance(subject, ObjectRef):
                    out.append(((subject.type, subject.id, node.via), negative))
                else:  # UsersetRef
                    out.append(((subject.type, subject.id, subject.relation), negative))
            self.direct_users[key] = self.direct_users.get(key, set()) | users
            return
        if isinstance(node, _ComputedUserset):
            out.append(((type_name, object_id, node.relation), negative))
            return
        if isinstance(node, _TupleToUserset):
            # The target is data-defined.  The edge keeps its polarity; if
            # such an edge closes a negative cycle in this instance graph,
            # the SCC check below raises NegativeRecursionError.
            for subject in self.store.object_subjects(type_name, object_id, node.tuple_relation):
                if isinstance(subject, UsersetRef):
                    raise InvalidSubjectError(
                        "tuple_userset relation %s#%s may only point at objects, "
                        "not usersets (got %s)"
                        % (type_name, node.tuple_relation, subject)
                    )
                out.append(((subject.type, subject.id, node.computed_relation), negative))
            return
        if isinstance(node, Union) or isinstance(node, Intersect):
            for child in node.children:
                self._collect(child, key, negative, out)
            return
        if isinstance(node, Difference):
            self._collect(node.base, key, negative, out)
            for child in node.subtracted:
                self._collect(child, key, True, out)
            return
        raise InvalidSubjectError("unsupported rewrite node %r" % node)

    # -- SCCs -------------------------------------------------------------

    def _tarjan(self):
        """Iterative Tarjan SCC; components are emitted sink-first."""
        index = {}
        low = {}
        on_stack = set()
        stack = []
        components = []
        counter = 0

        for source in self.edges:
            if source in index:
                continue
            index[source] = low[source] = counter
            counter += 1
            stack.append(source)
            on_stack.add(source)
            # Each work item is (node, iterator over its edges).
            work = [(source, iter(self.edges.get(source, ())))]
            while work:
                v, iterator = work[-1]
                descended = False
                for w, _ in iterator:
                    if w not in index:
                        index[w] = low[w] = counter
                        counter += 1
                        stack.append(w)
                        on_stack.add(w)
                        work.append((w, iter(self.edges.get(w, ()))))
                        descended = True
                        break
                    if w in on_stack:
                        low[v] = min(low[v], index[w])
                if descended:
                    continue
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[v])
                if low[v] == index[v]:
                    component = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        component.append(w)
                        if w == v:
                            break
                    components.append(component)
        return components

    # -- evaluation -------------------------------------------------------

    def solve(self, root):
        components = self._tarjan()
        values = {}
        # Tarjan emits components in reverse topological order: sinks first.
        for component in components:
            member = set(component)
            self._check_no_negative_cycle(component, member)
            outside = {
                child: values[child]
                for key in component
                for child, _ in self.edges.get(key, ())
                if child not in member
            }

            has_internal_edge = any(
                child in member for key in component for child, _ in self.edges.get(key, ())
            )
            if not has_internal_edge:
                # Every edge leaves the component, so dependencies were solved
                # in earlier (sink-first) components: one pass is exact.
                for key in component:
                    values[key] = self._eval(key, values)
                continue

            current = {key: set() for key in component}
            while True:
                updated = dict(current)
                for key in component:
                    lookup = dict(outside)
                    lookup.update(current)
                    updated[key] = self._eval(key, lookup)
                if updated == current:
                    break
                current = updated
            values.update(current)
        return values[root]

    def _check_no_negative_cycle(self, component, member):
        for key in component:
            for child, negative in self.edges.get(key, ()):
                if negative and child in member:
                    raise NegativeRecursionError(
                        "data tuples close a negative recursion cycle through "
                        "difference: %s depends on %s under subtraction" % (key, child)
                    )

    def _eval(self, key, values):
        type_name, object_id, relation = key
        rewrite = self.schema.rewrite(type_name, relation)
        return self._eval_node(rewrite, key, values)

    def _eval_node(self, node, key, values):
        type_name, object_id, relation = key
        if isinstance(node, _This):
            result = set(self.direct_users.get(key, set()))
            for subject in self.store.subjects(type_name, object_id, relation):
                if isinstance(subject, ObjectRef):
                    result |= values[(subject.type, subject.id, node.via)]
                elif isinstance(subject, UsersetRef):
                    result |= values[(subject.type, subject.id, subject.relation)]
            return result
        if isinstance(node, _ComputedUserset):
            # Return a copy: callers (notably Difference) may mutate it.
            return set(values[(type_name, object_id, node.relation)])
        if isinstance(node, _TupleToUserset):
            result = set()
            for subject in self.store.object_subjects(type_name, object_id, node.tuple_relation):
                result |= values[(subject.type, subject.id, node.computed_relation)]
            return result
        if isinstance(node, Union):
            result = set()
            for child in node.children:
                result |= self._eval_node(child, key, values)
            return result
        if isinstance(node, Intersect):
            result = None
            for child in node.children:
                value = self._eval_node(child, key, values)
                result = value if result is None else result & value
            return result if result is not None else set()
        if isinstance(node, Difference):
            result = set(self._eval_node(node.base, key, values))
            for child in node.subtracted:
                result -= self._eval_node(child, key, values)
            return result
        raise InvalidSubjectError("unsupported rewrite node %r" % node)
