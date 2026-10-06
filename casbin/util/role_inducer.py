# Copyright 2021 The casbin Authors. All Rights Reserved.
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

"""Read-only role induction (role mining) helper.

Migrates a legacy user -> permission direct-grant matrix to RBAC without
creating a dedicated role per user. Given a finite user set, a permission
set and the allow relation between them, :func:`induce_roles` searches for
candidate ``p``/``g`` policies such that:

- every role represents a subset of the permissions,
- the effective permissions of every user after role assignment are
  exactly the original grants (no privilege is ever widened or dropped),
- the caller-specified objective is lexicographic: minimize the number of
  roles first, then the number of user-role assignment edges,
- optional constraints forbid chosen permission pairs from belonging to
  the same role.

The search is a branch-and-bound with a node budget. When the budget is
exhausted before optimality is proven, the best feasible solution found so
far is returned with ``proven_optimal == False`` and
``budget_exhausted == True`` so callers can tell the plan is usable but
not certified optimal.

This module never touches an enforcer, model or adapter; it only computes
plain data. Use :meth:`RoleInductionResult.to_policy_text` to feed the
result into an independent enforcer for verification.
"""

from dataclasses import dataclass
from itertools import combinations

__all__ = ["InducedRole", "RoleInductionResult", "induce_roles"]

DEFAULT_ACT = "access"
DEFAULT_NODE_BUDGET = 100_000


class _BudgetExhausted(Exception):
    pass


@dataclass
class InducedRole:
    """A candidate role: a named subset of permissions."""

    name: str
    permissions: frozenset


@dataclass
class RoleInductionResult:
    """Outcome of :func:`induce_roles`.

    ``proven_optimal`` is True only when the search space was exhausted
    within the node budget. ``budget_exhausted`` marks that the search was
    cut short; in that case the returned plan is feasible (exact effective
    permissions) but a better one may exist.
    """

    roles: list
    assignments: dict
    proven_optimal: bool
    nodes_explored: int
    budget_exhausted: bool
    act: str = DEFAULT_ACT

    @property
    def role_count(self):
        return len(self.roles)

    @property
    def assignment_edge_count(self):
        return sum(len(names) for names in self.assignments.values())

    @property
    def objective(self):
        """Lexicographic objective: (role count, assignment edge count)."""
        return (self.role_count, self.assignment_edge_count)

    def effective_permissions(self, user):
        """Permissions ``user`` ends up with through the assigned roles."""
        by_name = {role.name: role.permissions for role in self.roles}
        effective = set()
        for name in self.assignments.get(user, []):
            effective |= by_name[name]
        return frozenset(effective)

    def p_policies(self):
        """``p`` rules: [role, permission, act] for every role permission."""
        rules = []
        for role in self.roles:
            for perm in sorted(role.permissions):
                rules.append([role.name, perm, self.act])
        return rules

    def g_policies(self):
        """``g`` rules: [user, role] for every assignment edge."""
        rules = []
        for user, names in self.assignments.items():
            for name in names:
                rules.append([user, name])
        return rules

    def to_policy_text(self):
        """Renders the plan as policy CSV text loadable by any adapter."""
        lines = ["p, " + ", ".join(rule) for rule in self.p_policies()]
        lines += ["g, " + ", ".join(rule) for rule in self.g_policies()]
        return "\n".join(lines) + "\n"


def _normalize_inputs(users, permissions, allow, forbidden_pairs):
    users = list(users)
    permissions = list(permissions)
    user_set = set(users)
    perm_set = set(permissions)
    if len(user_set) != len(users):
        raise ValueError("users must not contain duplicates")
    if len(perm_set) != len(permissions):
        raise ValueError("permissions must not contain duplicates")

    grants = {user: set() for user in users}
    for pair in allow:
        user, perm = pair
        if user not in user_set:
            raise ValueError(f"allow relation references unknown user: {user!r}")
        if perm not in perm_set:
            raise ValueError(f"allow relation references unknown permission: {perm!r}")
        grants[user].add(perm)

    forbidden = []
    for pair in forbidden_pairs or []:
        members = tuple(pair)
        if len(members) != 2:
            raise ValueError(f"forbidden constraint must be a permission pair: {members!r}")
        for perm in members:
            if perm not in perm_set:
                raise ValueError(f"forbidden constraint references unknown permission: {perm!r}")
        forbidden.append(frozenset(members))

    return users, permissions, grants, forbidden


def _respects_constraints(role_perms, forbidden):
    return not any(pair <= role_perms for pair in forbidden)


def _candidate_roles(target, forbidden):
    """All non-empty constraint-respecting subsets of one user's grants."""
    perms = sorted(target)
    candidates = []
    for size in range(1, len(perms) + 1):
        for combo in combinations(perms, size):
            role_perms = frozenset(combo)
            if _respects_constraints(role_perms, forbidden):
                candidates.append(role_perms)
    candidates.sort(key=lambda r: (-len(r), sorted(r)))
    return candidates


def _iter_exact_covers(candidates, target):
    """Yields irredundant exact covers of ``target`` built from ``candidates``.

    Each yielded cover is a list of candidate role sets whose union equals
    ``target`` and from which no role can be dropped without losing coverage.
    """
    seen = set()

    def rec(remaining, chosen):
        if not remaining:
            key = frozenset(chosen)
            if key not in seen:
                seen.add(key)
                if _is_irredundant(chosen, target):
                    yield list(chosen)
            return
        pivot = min(remaining)
        for role_perms in candidates:
            if pivot in role_perms:
                yield from rec(remaining - role_perms, chosen + [role_perms])

    yield from rec(set(target), [])


def _is_irredundant(cover, target):
    for i in range(len(cover)):
        rest = cover[:i] + cover[i + 1 :]
        union = set().union(*rest) if rest else set()
        if union == set(target):
            return False
    return True


def _drop_redundant(cover, target):
    """Removes roles whose permissions are already covered by the rest."""
    result = list(cover)
    changed = True
    while changed:
        changed = False
        for role_perms in list(result):
            rest = [r for r in result if r is not role_perms]
            union = set().union(*rest) if rest else set()
            if union == set(target):
                result.remove(role_perms)
                changed = True
    return result


def _greedy_solution(order, grants, candidates):
    """Feasible fallback plan: per-user greedy set cover, preferring reuse."""
    chosen = set()
    assignments = {}
    edges = 0
    for user in order:
        remaining = set(grants[user])
        cover = []
        while remaining:
            best = max(
                candidates[user],
                key=lambda r: (len(r & remaining), r in chosen, len(r)),
            )
            cover.append(best)
            remaining -= best
        cover = _drop_redundant(cover, grants[user])
        chosen.update(cover)
        assignments[user] = cover
        edges += len(cover)
    return chosen, edges, assignments


def induce_roles(
    users,
    permissions,
    allow,
    forbidden_pairs=None,
    node_budget=DEFAULT_NODE_BUDGET,
    act=DEFAULT_ACT,
):
    """Induces candidate RBAC roles from a direct user->permission matrix.

    Args:
        users: finite iterable of user identifiers.
        permissions: finite iterable of permission identifiers.
        allow: iterable of ``(user, permission)`` granted pairs.
        forbidden_pairs: optional iterable of permission pairs that must
            never belong to the same role.
        node_budget: maximum number of search nodes (cover options) to
            expand before returning the best plan found so far.
        act: action verb used in the generated ``p`` rules.

    Returns:
        A :class:`RoleInductionResult`. When ``node_budget`` runs out before
        the search completes, ``proven_optimal`` is False and
        ``budget_exhausted`` is True; the plan is still exact.

    Raises:
        ValueError: on unknown users/permissions or when the constraints
            make an exact solution impossible.
    """
    users, permissions, grants, forbidden = _normalize_inputs(
        users, permissions, allow, forbidden_pairs
    )

    candidates = {}
    for user in users:
        target = grants[user]
        candidates[user] = _candidate_roles(target, forbidden)
        for perm in target:
            if not any(perm in role for role in candidates[user]):
                raise ValueError(
                    f"no feasible role can cover permission {perm!r} of user {user!r} "
                    "under the forbidden-pair constraints"
                )

    # Users with the largest grant sets first: they constrain the search most.
    order = sorted(users, key=lambda u: (-len(grants[u]), str(u)))
    covers_by_user = {
        user: list(_iter_exact_covers(candidates[user], grants[user]))
        for user in order
        if grants[user]
    }
    # Number of users at positions after i that still need at least one edge.
    suffix_needs_edge = [0] * (len(order) + 1)
    for i in range(len(order) - 1, -1, -1):
        suffix_needs_edge[i] = suffix_needs_edge[i + 1] + (1 if grants[order[i]] else 0)

    best_roles, best_edges, best_assign = _greedy_solution(order, grants, candidates)

    nodes = 0
    exhausted = False

    def dfs(index, chosen, edges, assign):
        nonlocal nodes, best_roles, best_edges, best_assign, exhausted
        if index == len(order):
            cost = (len(chosen), edges)
            if cost < (len(best_roles), best_edges):
                best_roles, best_edges, best_assign = set(chosen), edges, dict(assign)
            return
        user = order[index]
        if not grants[user]:
            dfs(index + 1, chosen, edges, {**assign, user: []})
            return
        options = sorted(
            covers_by_user[user],
            key=lambda cov: (
                sum(1 for r in cov if r not in chosen),
                len(cov),
                [sorted(r) for r in cov],
            ),
        )
        for cover in options:
            nodes += 1
            if nodes > node_budget:
                exhausted = True
                raise _BudgetExhausted
            new_roles = [r for r in cover if r not in chosen]
            role_count = len(chosen) + len(new_roles)
            edge_count = edges + len(cover)
            if role_count > len(best_roles):
                continue
            if role_count == len(best_roles) and (
                edge_count + suffix_needs_edge[index + 1] >= best_edges
            ):
                continue
            dfs(
                index + 1,
                chosen | set(new_roles),
                edge_count,
                {**assign, user: cover},
            )

    try:
        dfs(0, set(), 0, {})
    except _BudgetExhausted:
        pass

    roles_sorted = sorted(best_roles, key=lambda r: (-len(r), sorted(r)))
    names = {role_perms: f"role_{i}" for i, role_perms in enumerate(roles_sorted)}
    roles = [InducedRole(names[r], r) for r in roles_sorted]
    assignments = {
        user: sorted(names[r] for r in best_assign.get(user, [])) for user in users
    }
    return RoleInductionResult(
        roles=roles,
        assignments=assignments,
        proven_optimal=not exhausted,
        nodes_explored=nodes,
        budget_exhausted=exhausted,
        act=act,
    )
