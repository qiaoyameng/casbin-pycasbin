# Copyright 2026 The casbin Authors. All Rights Reserved.
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

"""Role induction (role mining) for a direct user-permission matrix.

The inducer is read-only with respect to every enforcer/adapter: it only
consumes a finite matrix description and produces candidate policies.

A solution is a family of roles (permission subsets) together with a
user-to-role assignment such that the *effective* permission of every user is
exactly the row of the input matrix: roles are subsets of the user's row, so
no privilege can be gained, and the row must be fully covered.

Supported objective: ``"roles_first"`` minimizes the number of distinct
roles, breaking ties by the number of ``g`` (user-role assignment) edges.

``forbidden_pairs`` declares permissions that must never share a role (a
static separation-of-duty style constraint).

The search runs under a node budget. A feasible solution is always returned
(singleton roles). If the budget is exhausted before the branch-and-bound
search proves optimality, the result is explicitly marked as not proven.
"""

from dataclasses import dataclass, field
from itertools import combinations
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class InducedRole:
    """A candidate role: a named subset of permissions."""

    name: str
    permissions: Tuple[str, ...]


@dataclass(frozen=True)
class RoleInductionResult:
    """Candidate RBAC policy and provenance of the search."""

    roles: Tuple[InducedRole, ...]
    p_rules: Tuple[Tuple[str, ...], ...]
    g_rules: Tuple[Tuple[str, ...], ...]
    role_count: int
    assignment_edge_count: int
    objective: str
    optimal: bool
    status: str
    nodes_used: int
    node_budget: int
    forbidden_pairs: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)


class _BudgetReached(Exception):
    pass


def _validate_names(values, kind):
    names = list(values)
    if not names:
        return names, {}
    if any(not isinstance(name, str) or not name for name in names):
        raise ValueError("{} names must be non-empty strings".format(kind))
    if len(set(names)) != len(names):
        raise ValueError("{} names must be unique".format(kind))
    return names, {name: i for i, name in enumerate(names)}


def induce_roles(
    users,
    permissions,
    grants,
    forbidden_pairs=(),
    objective="roles_first",
    node_budget=100000,
    action="read",
    role_name_prefix="role_",
):
    """Induce a read-only RBAC policy from a direct authorization matrix.

    Args:
        users: finite collection of user names.
        permissions: finite collection of permission/object names.
        grants: finite collection of ``(user, permission)`` pairs describing
            the direct matrix. Only these cells are granted; every other
            (user, permission) cell must remain denied.
        forbidden_pairs: pairs of permissions that are not allowed to coexist
            in one role.
        objective: only ``"roles_first"`` is supported (fewest roles, then
            fewest assignment edges).
        node_budget: maximum number of search nodes. The function always
            returns a feasible solution; when the budget is consumed before
            optimality is proven, ``optimal`` is ``False`` and ``status`` is
            ``"budget_exhausted"``.
        action: action value used in the generated ``p`` rules.
        role_name_prefix: prefix for generated role names.

    Returns:
        RoleInductionResult
    """
    if objective != "roles_first":
        raise ValueError("unsupported objective: {!r}".format(objective))
    if not isinstance(node_budget, int) or node_budget <= 0:
        raise ValueError("node_budget must be a positive integer")
    if not isinstance(action, str) or not action:
        raise ValueError("action must be a non-empty string")
    if not isinstance(role_name_prefix, str) or not role_name_prefix:
        raise ValueError("role_name_prefix must be a non-empty string")

    user_names, user_index = _validate_names(users, "user")
    perm_names, perm_index = _validate_names(permissions, "permission")

    rows = [0] * len(user_names)
    for pair in grants:
        user, permission = pair
        if user not in user_index:
            raise ValueError("grant references unknown user: {!r}".format(user))
        if permission not in perm_index:
            raise ValueError(
                "grant references unknown permission: {!r}".format(permission)
            )
        rows[user_index[user]] |= 1 << perm_index[permission]

    forbidden = [0] * len(perm_names)
    normalized_pairs: List[Tuple[str, str]] = []
    for pair in forbidden_pairs:
        left, right = pair
        if left == right:
            raise ValueError("a permission cannot be forbidden with itself")
        if left not in perm_index or right not in perm_index:
            raise ValueError("forbidden pair references unknown permission")
        i, j = perm_index[left], perm_index[right]
        if i == j:
            raise ValueError("a permission cannot be forbidden with itself")
        forbidden[i] |= 1 << j
        forbidden[j] |= 1 << i
        lo, hi = sorted((left, right))
        normalized = (lo, hi)
        if normalized not in normalized_pairs:
            normalized_pairs.append(normalized)

    n = len(user_names)

    def compatible(mask):
        bits = mask
        while bits:
            bit = bits & -bits
            i = bit.bit_length() - 1
            if forbidden[i] & mask:
                return False
            bits ^= bit
        return True

    chrom_memo: Dict[int, int] = {0: 0}

    def chromatic(mask):
        """Exact chromatic number of the forbidden graph induced by mask."""
        cached = chrom_memo.get(mask)
        if cached is not None:
            return cached
        bit = mask & -mask
        v = bit.bit_length() - 1
        # Vertices that may share v's color class.
        avail = mask & ~forbidden[v] & ~bit
        best = None
        rest = avail
        while True:
            group = rest | bit
            if compatible(group):
                maximal = True
                leftover = mask & ~group
                check = leftover
                while check:
                    candidate = check & -check
                    c = candidate.bit_length() - 1
                    if not (forbidden[c] & group):
                        maximal = False
                        break
                    check ^= candidate
                if maximal:
                    value = 1 + chromatic(mask & ~group)
                    if best is None or value < best:
                        best = value
            if rest == 0:
                break
            rest = (rest - 1) & avail
        chrom_memo[mask] = best
        return best

    # Greedy feasible incumbent: reuse the largest fitting existing role,
    # otherwise create a largest compatible role covering the first missing
    # permission. Singleton fallback is always feasible.
    def greedy_solution():
        roles: List[int] = []
        assignment: List[List[int]] = [[] for _ in range(n)]
        edges = 0
        for ui in range(n):
            row = rows[ui]
            covered = 0
            while covered != row:
                missing = row & ~covered
                best_role = -1
                best_size = -1
                for idx, role_mask in enumerate(roles):
                    if (
                        role_mask & missing
                        and role_mask & ~row == 0
                        and not (role_mask & covered)
                    ):
                        size = role_mask.bit_count()
                        if size > best_size:
                            best_size = size
                            best_role = idx
                if best_role >= 0:
                    chosen = roles[best_role]
                    assignment[ui].append(best_role)
                else:
                    pivot = missing & -missing
                    chosen = pivot
                    candidates = missing & ~pivot
                    bits = candidates
                    while bits:
                        candidate = bits & -bits
                        if not (forbidden[candidate.bit_length() - 1] & chosen):
                            chosen |= candidate
                        bits ^= candidate
                    duplicate = -1
                    for idx, role_mask in enumerate(roles):
                        if role_mask == chosen:
                            duplicate = idx
                            break
                    if duplicate < 0:
                        duplicate = len(roles)
                        roles.append(chosen)
                    assignment[ui].append(duplicate)
                covered |= chosen
                edges += 1
        return tuple(roles), tuple(tuple(a) for a in assignment), edges

    incumbent_roles, incumbent_assignment, incumbent_edges = greedy_solution()

    nodes = 0

    def tick():
        nonlocal nodes
        nodes += 1
        if nodes > node_budget:
            raise _BudgetReached()

    def role_lb_after(roles, remaining_rows):
        """Lower bound on extra new roles beyond the existing roles.

        For each still-unassigned row (including the partially covered
        current row), the minimum number of new roles needed after optimally
        reusing assignable existing roles is computed exactly; taking the
        maximum across rows is a safe per-user bound because one new role can
        serve two rows only when it is a subset of both.
        """
        need = 0
        for row in remaining_rows:
            assignable = tuple(
                role_mask for role_mask in roles if role_mask & ~row == 0
            )
            best = chromatic(row)
            for size in range(1, len(assignable) + 1):
                for combo in combinations(assignable, size):
                    covered = 0
                    for role_mask in combo:
                        covered |= role_mask
                    value = chromatic(row & ~covered)
                    if value < best:
                        best = value
            if best > need:
                need = best
        return need

    incumbent = {
        "roles": incumbent_roles,
        "assignment": incumbent_assignment,
        "edges": incumbent_edges,
    }

    roles_work: List[int] = []
    assignment_work: List[List[int]] = [[] for _ in range(n)]

    def edge_lb(edges, ui, current_row_nonempty):
        bound = edges + (1 if current_row_nonempty else 0)
        for future_ui in range(ui + 1, n):
            if rows[future_ui]:
                bound += 1
        return bound

    def prune(ui, current_remaining, edges):
        best_roles = incumbent["roles"]
        remaining_rows = []
        if current_remaining:
            remaining_rows.append(current_remaining)
        remaining_rows.extend(
            rows[future_ui] for future_ui in range(ui + 1, n) if rows[future_ui]
        )
        role_lb = len(roles_work) + role_lb_after(
            roles_work, remaining_rows
        )
        if role_lb > len(best_roles):
            return True
        if role_lb == len(best_roles):
            edge_bound = edge_lb(edges, ui, bool(current_remaining))
            if edge_bound >= incumbent["edges"]:
                return True
        return False

    def consider_leaf(edges):
        best_roles = incumbent["roles"]
        if len(roles_work) < len(best_roles) or (
            len(roles_work) == len(best_roles) and edges < incumbent["edges"]
        ):
            incumbent["roles"] = tuple(roles_work)
            incumbent["assignment"] = tuple(
                tuple(assignment_work[ui]) for ui in range(n)
            )
            incumbent["edges"] = edges

    def exact_role_sets(mask):
        """All distinct sets of compatible roles whose union equals ``mask``.

        Roles may overlap and need not each introduce a new permission:
        assigning an already-covered role can be globally optimal when that
        role is shared with other users. Enumerating increasing-index
        combinations of compatible masks yields every unordered role set
        exactly once (including redundant and overlapping assignments).
        """
        compatible_masks = tuple(
            candidate
            for candidate in range(1, 1 << len(perm_names))
            if candidate & ~mask == 0 and compatible(candidate)
        )
        results = []

        def build(index, union, chosen):
            tick()
            if union == mask:
                results.append(tuple(chosen))
            for next_index in range(index, len(compatible_masks)):
                role_mask = compatible_masks[next_index]
                build(
                    next_index + 1,
                    union | role_mask,
                    chosen + [role_mask],
                )

        build(0, 0, [])
        return results

    def search(ui, edges):
        tick()
        if ui == n:
            consider_leaf(edges)
            return
        row = rows[ui]
        if row == 0:
            if not prune(ui, 0, edges):
                search(ui + 1, edges)
            return
        if prune(ui, row, edges):
            return

        role_sets = exact_role_sets(row)
        # Fewer assignment edges first to tighten the incumbent quickly.
        role_sets.sort(key=lambda chosen: (len(chosen), chosen))

        for chosen in role_sets:
            tick()

            # Reuse an existing identical role when present, otherwise
            # create it. Distinct role masks within one cover are guaranteed
            # by exact_role_sets; a role is never created twice globally.
            def assign(index):
                tick()
                if index == len(chosen):
                    if not prune(ui, 0, edges):
                        search(ui + 1, edges + len(chosen))
                    return
                role_mask = chosen[index]
                existing_index = -1
                for existing_idx, existing_mask in enumerate(roles_work):
                    if existing_mask == role_mask:
                        existing_index = existing_idx
                        break
                if existing_index >= 0:
                    assignment_work[ui].append(existing_index)
                    assign(index + 1)
                    assignment_work[ui].pop()
                    return
                new_index = len(roles_work)
                roles_work.append(role_mask)
                assignment_work[ui].append(new_index)
                assign(index + 1)
                assignment_work[ui].pop()
                roles_work.pop()

            assign(0)

    status = "optimal"
    try:
        search(0, 0)
    except _BudgetReached:
        status = "budget_exhausted"

    return _build_result(
        incumbent=incumbent,
        rows=rows,
        perm_names=perm_names,
        user_names=user_names,
        normalized_pairs=normalized_pairs,
        status=status,
        nodes=nodes,
        node_budget=node_budget,
        action=action,
        role_name_prefix=role_name_prefix,
    )


def _build_result(
    incumbent,
    rows,
    perm_names,
    user_names,
    normalized_pairs,
    status,
    nodes,
    node_budget,
    action,
    role_name_prefix,
):
    role_masks = incumbent["roles"]
    assignment = incumbent["assignment"]

    used = [False] * len(role_masks)
    for user_assignment in assignment:
        for idx in user_assignment:
            used[idx] = True

    ordered = [idx for idx, flag in enumerate(used) if flag]
    renumber = {old: new for new, old in enumerate(ordered)}

    induced_roles: List[InducedRole] = []
    p_rules: List[Tuple[str, ...]] = []
    for new_index, old_index in enumerate(ordered):
        mask = role_masks[old_index]
        permissions = tuple(
            perm_names[i] for i in range(len(perm_names)) if mask & (1 << i)
        )
        name = "{}{}".format(role_name_prefix, new_index)
        induced_roles.append(InducedRole(name=name, permissions=permissions))
        for permission in permissions:
            p_rules.append((name, permission, action))

    g_rules: List[Tuple[str, ...]] = []
    for ui, user in enumerate(user_names):
        role_ids = sorted(renumber[old] for old in assignment[ui])
        for new_index in role_ids:
            g_rules.append((user, induced_roles[new_index].name))

    p_rules.sort()
    g_rules.sort()

    return RoleInductionResult(
        roles=tuple(induced_roles),
        p_rules=tuple(p_rules),
        g_rules=tuple(g_rules),
        role_count=len(induced_roles),
        assignment_edge_count=len(g_rules),
        objective="roles_first",
        optimal=status == "optimal",
        status=status,
        nodes_used=min(nodes, node_budget),
        node_budget=node_budget,
        forbidden_pairs=tuple(normalized_pairs),
    )
