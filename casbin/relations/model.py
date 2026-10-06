"""Authorization model for relation tuples.

A model declares, per object type and relation, how the members of that
relation are computed:

* direct tuple subjects (:class:`This`),
* another relation on the same object (:class:`ComputedUserset`),
* a relation reached through a tuple relation on the object
  (:class:`TupleToUserset`),
* and boolean combinations (:class:`Union`, :class:`Intersection`,
  :class:`Difference`).

Models are validated at definition time. In particular, recursion that returns
to a relation through a subtraction operand ("negative recursion", e.g.
``x = this - x``) is rejected here -- never silently truncated at query time.
"""

from dataclasses import dataclass, field
from enum import Enum

from .entities import USER_TYPE


class SubjectKind(Enum):
    """What kinds of tuple subjects a relation accepts."""

    DIRECT_USER = "user"
    USERSET = "userset"
    OBJECT = "object"


@dataclass(frozen=True)
class AllowedSubject:
    """One entry of a relation's list of admissible tuple subjects."""

    kind: SubjectKind
    type_name: str
    relation: str = None


def direct_users():
    """Admissible direct users (``...@user:<id>``)."""

    return AllowedSubject(SubjectKind.DIRECT_USER, USER_TYPE)


def userset_of(type_name, relation):
    """Admissible userset subject (``...@<type>:<id>#<relation>``)."""

    return AllowedSubject(SubjectKind.USERSET, type_name, relation)


def object_of(type_name):
    """Admissible bare object subject (``...@<type>:<id>``)."""

    return AllowedSubject(SubjectKind.OBJECT, type_name)


class Node:
    """Base class of userset rewrite expressions."""

    def children(self):
        return ()

    def edges(self):
        """Static dependency edges contributed by this node.

        Returns a mapping of child node key -> set of signs. Sign ``-`` marks a
        dependency through a subtraction operand.
        """

        return {}


@dataclass(frozen=True)
class This(Node):
    """The direct tuple subjects of this relation."""


@dataclass(frozen=True)
class ComputedUserset(Node):
    """Another relation on the same object: ``object#<relation>``."""

    relation: str

    def edges(self):
        return {("_computed", self.relation): {"+"}}


@dataclass(frozen=True)
class TupleToUserset(Node):
    """Follow a tuple relation, then read a relation on each referenced object.

    With ``tupleset="parent"`` and ``computed_relation="viewer"`` this expands
    ``x.parent -> viewer`` (the OpenFGA ``tupleToUserset`` shape).
    """

    tupleset: str
    computed_relation: str

    def edges(self):
        return {("_ttu", self.tupleset, self.computed_relation): {"+"}}


class _Combination(Node):
    sign = "+"

    def __init__(self, *branches):
        if len(branches) < 2:
            raise ValueError(f"{type(self).__name__} needs at least two branches")
        for branch in branches:
            if not isinstance(branch, Node):
                raise TypeError("combination branches must be rewrite nodes")
        self.branches = tuple(branches)

    def children(self):
        return self.branches

    def __eq__(self, other):
        return isinstance(other, _Combination) and self.branches == other.branches

    def __hash__(self):
        return hash((type(self).__name__, self.branches))

    def __repr__(self):
        return f"{type(self).__name__}({', '.join(repr(b) for b in self.branches)})"

    def edges(self):
        result = {}
        for branch in self.branches:
            for key, signs in branch.edges().items():
                result.setdefault(key, set()).update(signs)
        return result


class Union(_Combination):
    """Union of the given usersets."""

    sign = "+"


class Intersection(_Combination):
    """Intersection of the given usersets."""

    sign = "+"


@dataclass(frozen=True, eq=False)
class Difference(Node):
    """``base - subtract`` set difference."""

    base: Node
    subtract: Node

    def __post_init__(self):
        if not isinstance(self.base, Node) or not isinstance(self.subtract, Node):
            raise TypeError("difference operands must be rewrite nodes")

    def children(self):
        return self.base, self.subtract

    def edges(self):
        result = {}
        for key, signs in self.base.edges().items():
            result.setdefault(key, set()).update(signs)
        for key, signs in self.subtract.edges().items():
            result.setdefault(key, set()).update({"-" if s == "+" else s for s in signs})
        return result


@dataclass
class RelationSpec:
    """Definition of one ``<type>#<relation>``."""

    type_name: str
    relation: str
    rewrite: Node = field(default_factory=This)
    allowed_subjects: tuple = (direct_users(),)

    def __post_init__(self):
        if not self.type_name or not isinstance(self.type_name, str):
            raise TypeError("type_name must be a non-empty string")
        if not self.relation or not isinstance(self.relation, str):
            raise TypeError("relation must be a non-empty string")
        if not isinstance(self.rewrite, Node):
            raise TypeError("rewrite must be a userset node")
        normalized = tuple(self.allowed_subjects)
        for allowed in normalized:
            if not isinstance(allowed, AllowedSubject):
                raise TypeError("allowed_subjects entries must be AllowedSubject")
            if allowed.kind in (SubjectKind.USERSET,) and not allowed.relation:
                raise ValueError("userset subject declaration needs a relation")
        self.allowed_subjects = normalized

    @property
    def node_key(self):
        return self.type_name, self.relation


class RelationModelError(ValueError):
    """Raised at model definition time for invalid relation models."""


class RelationModel:
    """Validated set of :class:`RelationSpec` definitions."""

    def __init__(self, specs):
        self._specs = {}
        for spec in specs:
            if not isinstance(spec, RelationSpec):
                raise TypeError("model entries must be RelationSpec")
            if spec.node_key in self._specs:
                raise RelationModelError(f"duplicate relation definition: {spec.type_name}#{spec.relation}")
            self._specs[spec.node_key] = spec
        self.type_names = {spec.type_name for spec in self._specs.values()}
        self._validate_references()
        self.dependencies = self._build_dependency_graph()
        self._reject_negative_recursion()

    @property
    def specs(self):
        return dict(self._specs)

    def get(self, type_name, relation):
        return self._specs.get((type_name, relation))

    def require(self, type_name, relation):
        spec = self.get(type_name, relation)
        if spec is None:
            raise RelationModelError(f"undefined relation {type_name}#{relation}")
        return spec

    def _iter_nodes(self, spec):
        stack = [spec.rewrite]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(node.children())

    def _validate_references(self):
        for spec in self._specs.values():
            for node in self._iter_nodes(spec):
                if isinstance(node, ComputedUserset):
                    if (spec.type_name, node.relation) not in self._specs:
                        raise RelationModelError(
                            f"{spec.type_name}#{spec.relation}: computed userset references "
                            f"undefined relation {spec.type_name}#{node.relation}"
                        )
                elif isinstance(node, TupleToUserset):
                    if (spec.type_name, node.tupleset) not in self._specs:
                        raise RelationModelError(
                            f"{spec.type_name}#{spec.relation}: tuple-to-userset tupleset "
                            f"{spec.type_name}#{node.tupleset} is undefined"
                        )
                    self._validate_tupleset(spec, node)

    def _validate_tupleset(self, spec, node):
        targets = self._ttu_targets(spec.type_name, node.tupleset)
        if not targets:
            raise RelationModelError(
                f"{spec.type_name}#{spec.relation}: tupleset {spec.type_name}#{node.tupleset} "
                "must accept bare object subjects to follow"
            )
        for target_type in targets:
            if target_type == USER_TYPE:
                raise RelationModelError(
                    f"{spec.type_name}#{spec.relation}: tupleset {spec.type_name}#{node.tupleset} "
                    "may point at users, cannot read a relation on them"
                )
            if (target_type, node.computed_relation) not in self._specs:
                raise RelationModelError(
                    f"{spec.type_name}#{spec.relation}: tuple-to-userset reaches undefined "
                    f"relation {target_type}#{node.computed_relation}"
                )

    def _build_dependency_graph(self):
        """Edges: source (type,relation) -> target (type,relation) with +/- signs."""

        dependencies = {key: {} for key in self._specs}
        for key, spec in self._specs.items():
            type_name, _ = key
            for node_key, signs in spec.rewrite.edges().items():
                if node_key[0] == "_computed":
                    target = (type_name, node_key[1])
                else:
                    target_types = self._ttu_targets(type_name, node_key[1])
                    computed_relation = node_key[2]
                    for target_type in target_types:
                        dependencies[key].setdefault(
                            (target_type, computed_relation), set()
                        ).update(signs)
                    continue
                dependencies[key].setdefault(target, set()).update(signs)
        return dependencies

    def _ttu_targets(self, type_name, tupleset):
        """Object types the tupleset may (bare-object) point to."""

        tupleset_spec = self.require(type_name, tupleset)
        return {allowed.type_name for allowed in tupleset_spec.allowed_subjects
                if allowed.kind is SubjectKind.OBJECT}

    def validate_tuple(self, entity_obj, relation, subj):
        """Validate one relation tuple against this model (called on insert)."""

        spec = self.get(entity_obj.type_name, relation)
        if spec is None:
            raise RelationModelError(
                f"tuple writes undefined relation {entity_obj.type_name}#{relation}"
            )
        accepted = {(allowed.kind, allowed.type_name, allowed.relation) for allowed in spec.allowed_subjects}
        if subj.is_direct_user:
            wanted = (SubjectKind.DIRECT_USER, USER_TYPE, None)
            target_ref = str(subj.user)
        elif subj.userset is not None:
            wanted = (SubjectKind.USERSET, subj.userset.object.type_name, subj.userset.relation.name)
            target_ref = str(subj.userset)
        else:
            wanted = (SubjectKind.OBJECT, subj.object.type_name, None)
            target_ref = str(subj.object)
        if wanted not in accepted:
            raise RelationModelError(
                f"subject {target_ref} is not allowed on {entity_obj}#{relation}"
            )
        if subj.userset is not None and self.get(*wanted[1:]) is None:
            raise RelationModelError(
                f"tuple points at undefined userset {target_ref}"
            )


    def _reject_negative_recursion(self):
        """Reject any recursion that returns to a relation through subtraction.

        Pure positive cycles (team nesting etc.) are allowed; an SCC containing
        a negative edge has no well-founded fixed point and is rejected here.
        """

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
            for target in self.dependencies.get(node, {}):
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

        for node in self._specs:
            if node not in indices:
                strongconnect(node)

        for component in components:
            members = set(component)
            negative = [(src, dst) for src in component
                        for dst, signs in self.dependencies.get(src, {}).items()
                        if dst in members and "-" in signs]
            if not negative:
                continue
            src, dst = negative[0]
            if src == dst:
                cycle = [src, src]
            else:
                cycle = self._negative_cycle(src, dst, members)
            chain = " -> ".join(f"{type_name}#{relation}" for type_name, relation in cycle)
            raise RelationModelError(
                "negative recursion through set difference is not allowed: "
                f"{chain}"
            )

    def _negative_cycle(self, src, dst, members):
        """Build a cycle using the negative edge src -dst plus a path dst -> src."""

        directed = {node: set() for node in members}
        for node in members:
            for target in self.dependencies.get(node, {}):
                if target in members:
                    directed[node].add(target)

        queue = [(dst, [dst])]
        seen = {dst}
        path = None
        while queue:
            current, trace = queue.pop(0)
            for target in directed.get(current, ()):
                if target not in members or target in seen:
                    continue
                if target == src:
                    path = trace + [src]
                    queue = []
                    break
                seen.add(target)
                queue.append((target, trace + [target]))
        if path is None:
            path = [dst, src]
        return [src] + path
