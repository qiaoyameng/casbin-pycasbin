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

"""Static schema for relationship tuples.

A schema maps object types to their relation rewrites.  Building a
:class:`Schema` validates every rewrite and rejects definitions whose
difference branches can reach back to the relation itself (negative
recursion), which cannot be given a least-fixpoint meaning on finite data.
"""

from .entities import (
    Node,
    _This,
    _TupleToUserset,
    _ComputedUserset,
    Union,
    Intersect,
    Difference,
)
from .errors import InvalidSchemaError, NegativeRecursionError


class TypeDefinition:
    """All relations known for one object type."""

    def __init__(self, name, relations):
        self.name = name
        self.relations = dict(relations)

    def get(self, relation):
        return self.relations.get(relation)

    def __contains__(self, relation):
        return relation in self.relations


class Schema:
    """An immutable collection of type definitions."""

    def __init__(self, types):
        normalized = {}
        for name, definition in types.items():
            if isinstance(definition, TypeDefinition):
                td = definition
            else:
                td = TypeDefinition(name, definition)
            normalized[td.name] = td
        self.types = normalized
        self._validate()

    def get_type(self, type_name):
        td = self.types.get(type_name)
        if td is None:
            raise InvalidSchemaError("unknown object type %r" % type_name)
        return td

    def rewrite(self, type_name, relation):
        return self.get_type(type_name).get(relation)

    def has(self, type_name, relation):
        td = self.types.get(type_name)
        return td is not None and relation in td

    # -- validation -------------------------------------------------------

    def _validate(self):
        for td in self.types.values():
            for relation, node in td.relations.items():
                if not isinstance(node, Node):
                    raise InvalidSchemaError(
                        "relation %s.%s must be defined with a rewrite node" % (td.name, relation)
                    )
                self._validate_node(td, relation, node)
        self._reject_negative_recursion()

    def _validate_node(self, td, relation, node):
        if isinstance(node, _This):
            return
        if isinstance(node, _ComputedUserset):
            if node.relation not in td.relations:
                raise InvalidSchemaError(
                    "relation %s.%s references undefined %s.%s"
                    % (td.name, relation, td.name, node.relation)
                )
            return
        if isinstance(node, _TupleToUserset):
            if node.tuple_relation not in td.relations:
                raise InvalidSchemaError(
                    "%s.%s follows tuples of undefined relation %s.%s"
                    % (td.name, relation, td.name, node.tuple_relation)
                )
            # The target object type comes from tuple data, so the computed
            # relation cannot be checked statically; the evaluator verifies
            # it against the schema at evaluation time.
            return
        if isinstance(node, (Union, Intersect)):
            for child in node.children:
                self._validate_node(td, relation, child)
            return
        if isinstance(node, Difference):
            self._validate_node(td, relation, node.base)
            for child in node.subtracted:
                self._validate_node(td, relation, child)
            return
        raise InvalidSchemaError("unsupported rewrite node %r in %s.%s" % (node, td.name, relation))

    def _reject_negative_recursion(self):
        # Build a dependency graph over (type, relation) nodes.
        #
        # An edge is positive unless it leaves a difference's subtracted
        # branch.  A tuple_userset step has no static destination (the
        # object type and the target object id are tuple data), so it is not
        # an edge here; if data tuples later close a negative cycle through
        # such a step, the evaluator detects it on the finite instance graph
        # and raises instead of evaluating the branch to false.
        positive = {}
        negative = {}

        def add(graph, src, dst):
            graph.setdefault(src, set()).add(dst)

        def walk(td, relation, node, negated):
            src = (td.name, relation)
            if isinstance(node, _This):
                return
            if isinstance(node, _ComputedUserset):
                add(negative if negated else positive, src, (td.name, node.relation))
                return
            if isinstance(node, _TupleToUserset):
                return
            if isinstance(node, (Union, Intersect)):
                # Intersection restricts but does not negate, so edges that
                # pass through it keep their current polarity.
                for child in node.children:
                    walk(td, relation, child, negated)
                return
            if isinstance(node, Difference):
                walk(td, relation, node.base, negated)
                for child in node.subtracted:
                    walk(td, relation, child, True)

        for td in self.types.values():
            for relation, node in td.relations.items():
                walk(td, relation, node, False)

        # A negative recursion is a directed cycle using at least one
        # negative edge: for a negative edge source -> target, "target" must
        # be able to reach "source" again.  Reachability is computed as a
        # least fixpoint over the finite graph (edges of either polarity).
        def reachable_from(start):
            seen = set()
            frontier = [start]
            while frontier:
                nxt = []
                for node in frontier:
                    for successor in positive.get(node, ()):
                        if successor not in seen:
                            seen.add(successor)
                            nxt.append(successor)
                    for successor in negative.get(node, ()):
                        if successor not in seen:
                            seen.add(successor)
                            nxt.append(successor)
                frontier = nxt
            return seen

        for source, targets in negative.items():
            for target in targets:
                if source in reachable_from(target):
                    raise NegativeRecursionError(
                        "negative recursion through difference is not allowed: "
                        "%s.%s subtracts %s.%s on a path that leads back to the "
                        "subtracted relation"
                        % (source[0], source[1], target[0], target[1])
                    )
