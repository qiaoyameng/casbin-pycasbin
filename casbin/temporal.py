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

"""Time-window authorization queries.

Given a half-open query window ``[window_start, window_end)`` expressed with
timezone-aware absolute times, this module computes exactly *when* a request
is authorized, instead of only whether it is authorized right now.

Validity intervals can be attached to role inheritance links (``g`` rules)
and to policy rules (``p`` rules) through
``Enforcer.add_named_link_validity_interval()`` and
``Enforcer.add_named_policy_validity_interval()``.  Along a single
inheritance path all links must be valid at the same time (intersection),
while alternative paths may chain after each other (union).  The per-rule
results are combined according to the model's allow/deny policy effect.

Arbitrary custom time functions (link condition functions, ``timeMatch``,
``eval()`` or user-registered matcher functions) cannot be evaluated over a
window, so interval queries reject models that use them.
"""

import ast
import operator
import re

from casbin.constant.constants import (
    ALLOW_AND_DENY_EFFECT,
    ALLOW_OVERRIDE_EFFECT,
    DENY_OVERRIDE_EFFECT,
    PRIORITY_EFFECT,
)
from casbin.effect import Effector, effect_to_bool
from casbin.rbac import default_role_manager
from casbin.util import generate_g_function, has_eval
from casbin.util.temporal import (
    clip_intervals,
    complement_intervals,
    ensure_aware_datetime,
    intersect_intervals,
    normalize_intervals,
    subtract_intervals,
    union_intervals,
)

# Built-in matcher functions whose result only depends on their arguments,
# never on the evaluation time.  Everything else (timeMatch, user-registered
# functions, ...) is rejected for interval queries.
PURE_MATCHER_FUNCTIONS = {
    "keyMatch",
    "keyMatch2",
    "keyMatch3",
    "keyMatch4",
    "keyMatch5",
    "regexMatch",
    "ipMatch",
    "globMatch",
}

_ALLOW_OVERRIDE = "allow_override"
_DENY_OVERRIDE = "deny_override"
_ALLOW_AND_DENY = "allow_and_deny"
_PRIORITY = "priority"

_COMPARE_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda left, right: left in right,
    ast.NotIn: lambda left, right: left not in right,
}

_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
}


class _IntervalSet:
    """marks a matcher sub-expression that varies over the query window."""

    __slots__ = ("intervals",)

    def __init__(self, intervals):
        self.intervals = intervals


class _QueryContext:
    """validated, query-independent facts about the model and the request."""

    def __init__(self, enforcer, rtype, ptype, etype, mtype, rvals):
        self.enforcer = enforcer
        self.rtype = rtype
        self.ptype = ptype
        self.etype = etype
        self.mtype = mtype
        self.r_tokens = enforcer.model["r"][rtype].tokens
        self.p_tokens = enforcer.model["p"][ptype].tokens
        if len(self.r_tokens) != len(rvals):
            raise RuntimeError("invalid request size")
        self.r_parameters = dict(zip(self.r_tokens, rvals))
        self.exp_string = enforcer.model["m"][mtype].value
        self.exp_ast = _parse_matcher(self.exp_string)
        self.g_types = list(enforcer.model["g"].keys()) if "g" in enforcer.model.keys() else []
        self.effect = _resolve_effect(enforcer.model["e"][etype].value)


def _split_enforce_context(rvals):
    from casbin.core_enforcer import EnforceContext

    rtype, ptype, etype, mtype = "r", "p", "e", "m"
    if len(rvals) != 0 and isinstance(rvals[0], EnforceContext):
        enforce_context = rvals[0]
        rtype = enforce_context.rtype
        ptype = enforce_context.ptype
        etype = enforce_context.etype
        mtype = enforce_context.mtype
        rvals = rvals[1:]
    return rtype, ptype, etype, mtype, rvals


def _parse_matcher(exp_string):
    expr = exp_string.replace("&&", "and").replace("||", "or")
    expr = re.sub(r"!(?!=)", "not ", expr)
    return ast.parse(expr.strip()).body[0].value


def _resolve_effect(effect_expr):
    if effect_expr == ALLOW_OVERRIDE_EFFECT:
        return _ALLOW_OVERRIDE
    if effect_expr == DENY_OVERRIDE_EFFECT:
        return _DENY_OVERRIDE
    if effect_expr == ALLOW_AND_DENY_EFFECT:
        return _ALLOW_AND_DENY
    if effect_expr == PRIORITY_EFFECT:
        return _PRIORITY
    raise RuntimeError(f"interval queries do not support the policy effect: {effect_expr}")


def _role_manager_has_condition_funcs(rm):
    roles = getattr(rm, "all_roles", None)
    if roles:
        for role in roles.values():
            if getattr(role, "link_condition_func_map", None):
                return True
    domain_managers = getattr(rm, "rm_map", None)
    if domain_managers:
        return any(_role_manager_has_condition_funcs(manager) for manager in domain_managers.values())
    return False


def _check_interval_query_supported(enforcer, ctx):
    """rejects models whose time behaviour cannot be evaluated exactly."""
    for cond_rm in enforcer.cond_rm_map.values():
        if _role_manager_has_condition_funcs(cond_rm):
            raise RuntimeError(
                "interval queries do not support custom link condition functions; "
                "attach validity intervals with add_named_link_validity_interval() instead"
            )

    for rm in list(enforcer.rm_map.values()) + list(enforcer.cond_rm_map.values()):
        if getattr(rm, "matching_func", None) is not None or getattr(rm, "domain_matching_func", None) is not None:
            raise RuntimeError("interval queries do not support role pattern matching functions")

    for gtype in ctx.g_types:
        if len(enforcer.model["g"][gtype].tokens) != 2:
            raise RuntimeError("interval queries do not support domain-based role definitions")

    if has_eval(ctx.exp_string):
        raise RuntimeError("interval queries do not support eval() in the matcher")

    called_functions = set()
    for node in ast.walk(ctx.exp_ast):
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise RuntimeError("interval queries do not support indirect function calls in the matcher")
            called_functions.add(node.func.id)
    for name in sorted(called_functions):
        if name in ctx.g_types or name in PURE_MATCHER_FUNCTIONS:
            continue
        raise RuntimeError(
            f"interval queries do not support the matcher function '{name}'; "
            "custom or time-dependent functions (such as timeMatch) cannot be evaluated over a time window"
        )


def _prepare_context(enforcer, rvals):
    rtype, ptype, etype, mtype, rvals = _split_enforce_context(rvals)

    if "m" not in enforcer.model.keys():
        raise RuntimeError("model is undefined")
    if "m" not in enforcer.model["m"].keys():
        raise RuntimeError("model is undefined")

    ctx = _QueryContext(enforcer, rtype, ptype, etype, mtype, rvals)
    _check_interval_query_supported(enforcer, ctx)
    return ctx


def _make_g_interval_function(adjacency, max_level, window_list):
    """returns g(name1, name2) as the exact set of times the link holds.

    The result is the union over every inheritance path of the intersection
    of the path's link validity intervals, so separate paths may chain after
    each other while every link on one path must be valid simultaneously.
    """

    def g_interval_function(name1, name2):
        if name1 == name2:
            return list(window_list)

        collected = []

        def dfs(node, current_set, depth, visited):
            if depth > max_level:
                return
            for next_name, edge_set in adjacency.get(node, ()):
                if next_name in visited:
                    continue
                path_set = intersect_intervals(current_set, edge_set)
                if not path_set:
                    continue
                if next_name == name2:
                    collected.extend(path_set)
                else:
                    dfs(next_name, path_set, depth + 1, visited | {next_name})

        dfs(name1, list(window_list), 0, {name1})
        return normalize_intervals(collected)

    return g_interval_function


def _build_g_interval_functions(enforcer, ctx, window):
    window_list = [window]
    functions = {}
    for gtype in ctx.g_types:
        adjacency = {}
        for rule in enforcer.model["g"][gtype].policy:
            user, role = rule[0], rule[1]
            interval = enforcer.link_validity_intervals.get((gtype, user, role))
            if interval is None:
                edge_set = window_list
            else:
                edge_set = clip_intervals([interval], window)
            adjacency.setdefault(user, []).append((role, edge_set))
        max_level = 10
        rm = enforcer.rm_map.get(gtype)
        if rm is not None:
            max_level = getattr(rm, "max_hierarchy_level", 10)
        functions[gtype] = _make_g_interval_function(adjacency, max_level, window_list)
    return functions


class _IntervalMatcherEval:
    """evaluates a matcher AST over the query window.

    Boolean operators are lifted to exact interval-set operations; every
    other sub-expression is evaluated to a concrete, time-independent value.
    """

    def __init__(self, names, g_functions, pure_functions, window):
        self.names = names
        self.g_functions = g_functions
        self.pure_functions = pure_functions
        self.window = window

    def eval_to_intervals(self, node):
        return self._as_intervals(self.eval(node))

    def _as_intervals(self, value):
        if isinstance(value, _IntervalSet):
            return value.intervals
        if isinstance(value, bool):
            return [self.window] if value else []
        if isinstance(value, (int, float)):
            return [self.window] if value != 0 else []
        raise RuntimeError("matcher result should be bool, int or float")

    def _as_concrete(self, value):
        if isinstance(value, _IntervalSet):
            raise RuntimeError("interval queries only support combining g() results with boolean operators")
        return value

    def eval(self, node):
        if isinstance(node, ast.BoolOp):
            values = [self.eval_to_intervals(value) for value in node.values]
            if isinstance(node.op, ast.And):
                result = values[0]
                for value in values[1:]:
                    result = intersect_intervals(result, value)
                return _IntervalSet(result)
            if isinstance(node.op, ast.Or):
                return _IntervalSet(union_intervals(*values))
            raise RuntimeError(f"interval queries do not support the boolean operator: {ast.dump(node.op)}")

        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                return _IntervalSet(complement_intervals(self.eval_to_intervals(node.operand), self.window))
            if isinstance(node.op, (ast.USub, ast.UAdd)):
                operand = self._as_concrete(self.eval(node.operand))
                return -operand if isinstance(node.op, ast.USub) else +operand
            raise RuntimeError(f"interval queries do not support the unary operator: {ast.dump(node.op)}")

        if isinstance(node, ast.Compare):
            left = self._as_concrete(self.eval(node.left))
            for op, comparator in zip(node.ops, node.comparators):
                right = self._as_concrete(self.eval(comparator))
                op_func = _COMPARE_OPERATORS.get(type(op))
                if op_func is None:
                    raise RuntimeError(f"interval queries do not support the comparison: {ast.dump(op)}")
                if not op_func(left, right):
                    return False
                left = right
            return True

        if isinstance(node, ast.Call):
            if node.keywords:
                raise RuntimeError("interval queries do not support keyword arguments in the matcher")
            name = node.func.id
            args = [self._as_concrete(self.eval(arg)) for arg in node.args]
            if name in self.g_functions:
                return _IntervalSet(self.g_functions[name](*args))
            func = self.pure_functions.get(name)
            if func is None:
                raise RuntimeError(f"interval queries do not support the matcher function '{name}'")
            return func(*args)

        if isinstance(node, ast.Name):
            if node.id not in self.names:
                raise RuntimeError(f"unknown name '{node.id}' in the matcher")
            return self.names[node.id]

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.IfExp):
            test = self._as_concrete(self.eval(node.test))
            return self.eval(node.body if test else node.orelse)

        if isinstance(node, ast.BinOp):
            op_func = _BINARY_OPERATORS.get(type(node.op))
            if op_func is None:
                raise RuntimeError(f"interval queries do not support the operator: {ast.dump(node.op)}")
            left = self._as_concrete(self.eval(node.left))
            right = self._as_concrete(self.eval(node.right))
            return op_func(left, right)

        if isinstance(node, (ast.List, ast.Tuple)):
            return [self._as_concrete(self.eval(element)) for element in node.elts]

        raise RuntimeError(f"interval queries do not support the matcher syntax: {ast.dump(node)}")


def _combine_effects(effect, rule_sets, window):
    """combines (intervals, eft) pairs into the final allowed intervals."""
    allow_sets = [intervals for intervals, eft in rule_sets if eft == "allow"]
    deny_sets = [intervals for intervals, eft in rule_sets if eft == "deny"]

    if effect == _ALLOW_OVERRIDE:
        return union_intervals(*allow_sets)
    if effect == _DENY_OVERRIDE:
        return complement_intervals(union_intervals(*deny_sets), window)
    if effect == _ALLOW_AND_DENY:
        return subtract_intervals(union_intervals(*allow_sets), union_intervals(*deny_sets))

    # priority: the first matching rule in policy order decides each moment.
    result = []
    covered = []
    for intervals, eft in rule_sets:
        effective = subtract_intervals(intervals, covered)
        if eft == "allow":
            result = union_intervals(result, effective)
        covered = union_intervals(covered, intervals)
    return result


def get_allowed_intervals(enforcer, window_start, window_end, *rvals):
    """returns the sorted, non-overlapping half-open intervals inside
    [window_start, window_end) during which the request is allowed.

    Both bounds must be timezone-aware absolute times; the machine clock is
    never consulted.
    """
    window_start = ensure_aware_datetime(window_start, "window_start")
    window_end = ensure_aware_datetime(window_end, "window_end")
    if window_start > window_end:
        raise ValueError("window_start must not be after window_end")
    if window_start == window_end:
        return []

    if not enforcer.enabled:
        return [(window_start, window_end)]

    ctx = _prepare_context(enforcer, rvals)
    window = (window_start, window_end)

    g_functions = _build_g_interval_functions(enforcer, ctx, window)
    available_functions = enforcer.fm.get_functions()
    pure_functions = {name: available_functions[name] for name in PURE_MATCHER_FUNCTIONS if name in available_functions}

    rule_sets = []
    p_assertion = enforcer.model["p"][ctx.ptype]
    if len(p_assertion.policy) != 0:
        for pvals in p_assertion.policy:
            if len(ctx.p_tokens) != len(pvals):
                raise RuntimeError("invalid policy size")

            names = dict(ctx.r_parameters)
            names.update(zip(ctx.p_tokens, pvals))
            evaluator = _IntervalMatcherEval(names, g_functions, pure_functions, window)
            matched = evaluator.eval_to_intervals(ctx.exp_ast)
            if not matched:
                continue

            validity = enforcer.policy_validity_intervals.get((ctx.ptype, tuple(pvals)))
            if validity is not None:
                matched = intersect_intervals(matched, clip_intervals([validity], window))
                if not matched:
                    continue

            eft = names.get(ctx.ptype + "_eft", "allow")
            if eft not in ("allow", "deny"):
                continue
            rule_sets.append((matched, eft))
    else:
        names = dict(ctx.r_parameters)
        for token in ctx.p_tokens:
            names[token] = ""
        evaluator = _IntervalMatcherEval(names, g_functions, pure_functions, window)
        matched = evaluator.eval_to_intervals(ctx.exp_ast)
        if matched:
            rule_sets.append((matched, "allow"))

    return _combine_effects(ctx.effect, rule_sets, window)


def is_allowed_at(enforcer, moment, *rvals):
    """decides whether the request is allowed at one absolute moment.

    ``moment`` must be a timezone-aware absolute time; the machine clock is
    never consulted.  This is the point-in-time counterpart of
    get_allowed_intervals() and evaluates through the regular matcher and
    effector pipeline with only the currently valid links and policy rules.
    """
    moment = ensure_aware_datetime(moment, "moment")
    if not enforcer.enabled:
        return True

    ctx = _prepare_context(enforcer, rvals)

    functions = dict(enforcer.fm.get_functions())
    for gtype in ctx.g_types:
        max_level = 10
        rm = enforcer.rm_map.get(gtype)
        if rm is not None:
            max_level = getattr(rm, "max_hierarchy_level", 10)
        snapshot_rm = default_role_manager.RoleManager(max_level)
        for rule in enforcer.model["g"][gtype].policy:
            user, role = rule[0], rule[1]
            interval = enforcer.link_validity_intervals.get((gtype, user, role))
            if interval is None or (interval[0] <= moment < interval[1]):
                snapshot_rm.add_link(user, role)
        functions[gtype] = generate_g_function(snapshot_rm)

    expression = enforcer._get_expression(ctx.exp_string, functions)

    policy_effects = set()
    p_assertion = enforcer.model["p"][ctx.ptype]
    if len(p_assertion.policy) != 0:
        for pvals in p_assertion.policy:
            if len(ctx.p_tokens) != len(pvals):
                raise RuntimeError("invalid policy size")

            validity = enforcer.policy_validity_intervals.get((ctx.ptype, tuple(pvals)))
            if validity is not None and not (validity[0] <= moment < validity[1]):
                continue

            parameters = dict(ctx.r_parameters)
            parameters.update(zip(ctx.p_tokens, pvals))
            result = expression.eval(parameters)

            if isinstance(result, bool):
                if not result:
                    policy_effects.add(Effector.INDETERMINATE)
                    continue
            elif isinstance(result, float):
                if 0 == result:
                    policy_effects.add(Effector.INDETERMINATE)
                    continue
            else:
                raise RuntimeError("matcher result should be bool, int or float")

            p_eft_key = ctx.ptype + "_eft"
            if p_eft_key in parameters.keys():
                eft = parameters[p_eft_key]
                if "allow" == eft:
                    policy_effects.add(Effector.ALLOW)
                elif "deny" == eft:
                    policy_effects.add(Effector.DENY)
                else:
                    policy_effects.add(Effector.INDETERMINATE)
            else:
                policy_effects.add(Effector.ALLOW)

            if enforcer.eft.intermediate_effect(policy_effects) != Effector.INDETERMINATE:
                break
    else:
        parameters = dict(ctx.r_parameters)
        for token in ctx.p_tokens:
            parameters[token] = ""
        result = expression.eval(parameters)
        if result:
            policy_effects.add(Effector.ALLOW)
        else:
            policy_effects.add(Effector.INDETERMINATE)

    return effect_to_bool(enforcer.eft.final_effect(policy_effects))
