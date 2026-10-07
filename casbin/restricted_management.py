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

"""Restricted (delegated) policy management.

This module implements a management entry point for tenant administrators.
A delegated administrator is described by an :class:`AdminScope`: a finite
set of manageable subjects, objects and actions (any dimension may also be
declared unrestricted).  Instead of applying a batch of policy changes
directly, :class:`ScopedPolicyManager` first computes the *effective
authorization* of the candidate state (current policy + the proposed batch)
and proves that every newly granted request stays inside the administrator's
scope.  The check is semantic, not textual: it evaluates the candidate model,
so role inheritance chains, wildcard/matching functions and permission
expansion caused by removing ``deny`` rules are all taken into account.

The verification is conservative.  Only constructs whose effect can be
proven are supported:

* equality / inequality / membership tests of request attributes against
  policy values or literals,
* grouping functions ``g(...)`` (role inheritance, including domains),
* the built-in matching functions (``keyMatch``, ``keyMatch2``, ...,
  ``regexMatch``, ``globMatch``, ``ipMatch``) when the pattern language is
  provably a single literal value, or when the corresponding scope dimension
  is unrestricted.

Anything else (ABAC attribute access, ``eval()``, custom functions, ...)
raises :class:`UnsupportedModelError`.  When containment cannot be proven
the whole batch is rejected; not a single rule is written to the adapter
unless the entire batch verifies.
"""

import ast
import copy
import itertools
import re

from casbin.core_enforcer import EnforceContext
from casbin.enforcer import Enforcer


class ScopeViolationError(Exception):
    """raised when a batch would grant effective permissions outside the
    administrator's manageable scope.

    The ``witness`` attribute holds a concrete request tuple that the
    candidate policy state would newly allow and that lies outside the
    scope.
    """

    def __init__(self, message, witness=None):
        super().__init__(message)
        self.witness = witness


class UnsupportedModelError(Exception):
    """raised when scoped verification cannot prove that the effective
    authorization of the candidate policy state stays inside the scope."""


_UNSET = object()


class AdminScope:
    """the set of permissions a delegated (tenant) administrator may grant.

    Each request attribute (``sub``, ``obj``, ``act``, ...) maps to either a
    finite collection of manageable values or ``None`` meaning the attribute
    is unrestricted.  Attributes used by the model but absent from the scope
    raise :class:`UnsupportedModelError` during verification.

    >>> scope = AdminScope(subjects={"alice", "bob"}, objects={"data1"}, actions={"read"})
    >>> scope = AdminScope(domains={"sub": {"alice"}, "obj": None, "act": {"read"}})
    """

    def __init__(self, subjects=_UNSET, objects=_UNSET, actions=_UNSET, domains=None):
        self._domains = {}
        if domains:
            for name, values in domains.items():
                self._domains[name] = self._normalize(values)
        for name, values in (("sub", subjects), ("obj", objects), ("act", actions)):
            if values is not _UNSET:
                self._domains[name] = self._normalize(values)

    @staticmethod
    def _normalize(values):
        if values is None:
            return None
        return frozenset(values)

    def domain_for(self, attribute):
        """returns the manageable values for a request attribute, or None
        when the attribute is unrestricted."""
        if attribute not in self._domains:
            raise UnsupportedModelError(
                "administrator scope does not define a manageable domain "
                "for request attribute '%s'" % attribute
            )
        return self._domains[attribute]

    def contains(self, attribute, value):
        domain = self.domain_for(attribute)
        return domain is None or value in domain


class PolicyChange:
    """a single proposed policy mutation inside a batch."""

    ADD = "add"
    REMOVE = "remove"

    def __init__(self, op, sec, ptype, rule):
        if op not in (self.ADD, self.REMOVE):
            raise ValueError("invalid policy change operation '%s'" % op)
        if sec not in ("p", "g"):
            raise ValueError("invalid policy change section '%s'" % sec)
        self.op = op
        self.sec = sec
        self.ptype = ptype
        self.rule = tuple(rule)

    @classmethod
    def add_policy(cls, rule, ptype="p"):
        return cls(cls.ADD, "p", ptype, rule)

    @classmethod
    def remove_policy(cls, rule, ptype="p"):
        return cls(cls.REMOVE, "p", ptype, rule)

    @classmethod
    def add_grouping_policy(cls, rule, ptype="g"):
        return cls(cls.ADD, "g", ptype, rule)

    @classmethod
    def remove_grouping_policy(cls, rule, ptype="g"):
        return cls(cls.REMOVE, "g", ptype, rule)

    def __repr__(self):
        return "PolicyChange(%s, %s, %s, %r)" % (self.op, self.sec, self.ptype, list(self.rule))


# built-in matching functions whose pattern argument scoped verification can
# reason about.  Functions registered in the FunctionMap but absent here
# (keyGet, rangeMatch, custom functions, ...) are rejected as unsupported.
_PATTERN_FUNCS = (
    "keyMatch",
    "keyMatch2",
    "keyMatch3",
    "keyMatch4",
    "keyMatch5",
    "regexMatch",
    "globMatch",
    "ipMatch",
    "timeMatch",
)

_PROBE = "\x00out-of-scope\x00"


def _is_literal_pattern(func, pattern):
    """whether the language matched by ``pattern`` under ``func`` is provably
    exactly the singleton ``{pattern}``."""
    if not isinstance(pattern, str):
        return False
    if func == "keyMatch":
        return "*" not in pattern
    if func == "keyMatch2":
        return "*" not in pattern and ":" not in pattern
    if func in ("keyMatch3", "keyMatch4"):
        return "*" not in pattern and "{" not in pattern
    if func == "keyMatch5":
        return "*" not in pattern and "{" not in pattern and "?" not in pattern
    if func == "globMatch":
        return re.search(r"[*?\[\]{}\\]", pattern) is None
    if func == "ipMatch":
        return "/" not in pattern
    # regexMatch relies on re.match (prefix semantics): even a plain literal
    # matches longer strings, so its language is not provably finite here.
    # timeMatch compares against clock windows and is not enumerable either.
    return False


def _pattern_probes(pattern):
    """representative request values a wildcard pattern is likely to match;
    used to surface concrete out-of-scope witnesses during enumeration."""
    probes = {
        pattern,
        pattern + _PROBE,
        _PROBE + pattern,
        pattern.replace("*", _PROBE),
        pattern.replace("*", _PROBE) + _PROBE,
        re.sub(r"\{[^}]*\}", "x", pattern),
        re.sub(r":[^/]+", "x", pattern),
    }
    return {p for p in probes if isinstance(p, str)}


class _Unsupported(Exception):
    pass


class _MatcherAnalysis:
    def __init__(self):
        self.constants = set()  # string literals appearing in the matcher
        # (func_name, r_token, ("p", p_token) | ("const", value)) tuples:
        self.pattern_usages = []
        # r_token -> grouping function name, for calls like g(r_sub, ...):
        self.role_attrs = {}
        self.error = None


def _preprocess_matcher(expr):
    # mirror CoreEnforcer._get_expression so the AST matches what is evaluated
    expr = expr.replace("&&", "and").replace("||", "or")
    expr = re.sub(r"!(?!=)", "not ", expr)
    return expr


def _classify(node, r_tokens, p_tokens):
    if isinstance(node, ast.Name):
        if node.id in r_tokens:
            return "r"
        if node.id in p_tokens:
            return "p"
        return "other"
    if isinstance(node, ast.Constant):
        return "const"
    if isinstance(node, ast.Call):
        return "call"
    return "other"


def _check_node(node, r_tokens, p_tokens, g_names, analysis):
    if isinstance(node, ast.BoolOp):
        if not isinstance(node.op, (ast.And, ast.Or)):
            raise _Unsupported("unsupported boolean operator in matcher")
        for value in node.values:
            _check_node(value, r_tokens, p_tokens, g_names, analysis)
    elif isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, ast.Not):
            raise _Unsupported("unsupported unary operator in matcher")
        _check_node(node.operand, r_tokens, p_tokens, g_names, analysis)
    elif isinstance(node, ast.Compare):
        _check_compare(node, r_tokens, p_tokens, g_names, analysis)
    elif isinstance(node, ast.Call):
        _check_call(node, r_tokens, p_tokens, g_names, analysis)
    elif isinstance(node, ast.Constant):
        analysis.constants.add(node.value)
    elif isinstance(node, ast.Name):
        if node.id not in r_tokens and node.id not in p_tokens:
            raise _Unsupported("unknown name '%s' in matcher" % node.id)
    else:
        raise _Unsupported(
            "unsupported expression '%s' in matcher" % type(node).__name__
        )


def _check_compare(node, r_tokens, p_tokens, g_names, analysis):
    operands = [node.left] + list(node.comparators)
    kinds = []
    for operand in operands:
        kind = _classify(operand, r_tokens, p_tokens)
        if kind == "other" and isinstance(operand, (ast.Tuple, ast.List)):
            kind = "seq"
            for elt in operand.elts:
                elt_kind = _classify(elt, r_tokens, p_tokens)
                if elt_kind == "const":
                    analysis.constants.add(elt.value)
                elif elt_kind != "p":
                    raise _Unsupported(
                        "unsupported element in matcher literal collection"
                    )
        kinds.append(kind)

    if "other" in kinds:
        raise _Unsupported("unsupported operand in matcher comparison")
    if "call" in kinds:
        raise _Unsupported("function calls inside comparisons are not supported")
    if kinds.count("r") > 1:
        raise _Unsupported(
            "comparisons between request attributes are not supported"
        )
    if "r" in kinds:
        for op in node.ops:
            if not isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)):
                raise _Unsupported(
                    "only ==, !=, in and not in are supported for request attributes"
                )
        if "seq" in kinds and not any(
            isinstance(op, (ast.In, ast.NotIn)) for op in node.ops
        ):
            raise _Unsupported("literal collections require an 'in' comparison")
    for operand, kind in zip(operands, kinds):
        if kind == "const":
            analysis.constants.add(operand.value)


def _check_call(node, r_tokens, p_tokens, g_names, analysis):
    if not isinstance(node.func, ast.Name):
        raise _Unsupported("unsupported callable in matcher")
    if node.keywords:
        raise _Unsupported("keyword arguments in matcher calls are not supported")
    fname = node.func.id
    if fname in g_names:
        for i, arg in enumerate(node.args):
            kind = _classify(arg, r_tokens, p_tokens)
            if kind == "const":
                analysis.constants.add(arg.value)
            elif kind == "r":
                if i == 0:
                    analysis.role_attrs[arg.id] = fname
            elif kind != "p":
                raise _Unsupported("unsupported argument to '%s' in matcher" % fname)
    elif fname in _PATTERN_FUNCS:
        r_args = []
        patterns = []
        for arg in node.args:
            kind = _classify(arg, r_tokens, p_tokens)
            if kind == "r":
                r_args.append(arg.id)
            elif kind == "p":
                patterns.append(("p", arg.id))
            elif kind == "const":
                analysis.constants.add(arg.value)
                patterns.append(("const", arg.value))
            else:
                raise _Unsupported("unsupported argument to '%s' in matcher" % fname)
        for r_token in r_args:
            for source in patterns:
                analysis.pattern_usages.append((fname, r_token, source))
    else:
        raise _Unsupported(
            "function '%s' is not supported by scoped verification" % fname
        )


def _analyze_matcher(expr, r_tokens, p_tokens, g_names):
    analysis = _MatcherAnalysis()
    try:
        root = ast.parse(_preprocess_matcher(expr).strip()).body[0].value
        _check_node(root, r_tokens, p_tokens, g_names, analysis)
    except _Unsupported as exc:
        analysis.error = str(exc)
    except (SyntaxError, IndexError) as exc:
        analysis.error = "matcher cannot be parsed: %s" % exc
    return analysis


class ScopedPolicyManager:
    """restricted management entry point for a delegated administrator.

    ``apply()`` validates the *whole* batch before anything is written: the
    proposed changes are simulated on an in-memory copy of the model, the
    effective authorization of the candidate state is enumerated, and every
    newly granted request must fall inside ``scope``.  Only when the entire
    batch verifies are the changes applied to the enforcer (and thereby to
    its adapter); a single failing change rejects the whole batch.

    A name is treated as a role (rather than a real subject) when it appears
    as a parent in the candidate grouping policy; permissions granted to
    roles are checked through the members that inherit them.  Attach members
    to newly created roles in the same batch so the role is recognized.

    Limitations of this first version: verification is based on explicit
    finite domains plus the built-in matching functions, and conditional
    (temporal) role managers are not supported.  Whenever containment cannot
    be proven, the batch is rejected with :class:`UnsupportedModelError`.
    """

    def __init__(self, enforcer, scope, max_checks=200000):
        self.enforcer = enforcer
        self.scope = scope
        self.max_checks = max_checks

    def verify(self, changes):
        """validates a batch without applying it; raises ScopeViolationError,
        UnsupportedModelError or ValueError on failure."""
        changes = self._normalize_changes(changes)
        self._verify(changes)
        return True

    def apply(self, changes):
        """verifies the whole batch and, only if it is fully inside the
        administrator's scope, applies every change to the enforcer."""
        changes = self._normalize_changes(changes)
        self._verify(changes)
        for change in changes:
            if not self._apply_change(change):
                raise RuntimeError(
                    "failed to apply verified change %r; the enforcer state "
                    "changed while the batch was being applied" % (change,)
                )
        return True

    @staticmethod
    def _normalize_changes(changes):
        normalized = []
        for change in changes:
            if not isinstance(change, PolicyChange):
                raise TypeError(
                    "expected PolicyChange instances, got %r" % (change,)
                )
            normalized.append(change)
        return normalized

    def _apply_change(self, change):
        enforcer = self.enforcer
        if change.sec == "p":
            if change.op == PolicyChange.ADD:
                return enforcer.add_named_policy(change.ptype, *change.rule)
            return enforcer.remove_named_policy(change.ptype, *change.rule)
        if change.op == PolicyChange.ADD:
            return enforcer.add_named_grouping_policy(change.ptype, *change.rule)
        return enforcer.remove_named_grouping_policy(change.ptype, *change.rule)

    def _validate_change(self, model, change):
        if change.sec not in model.keys() or change.ptype not in model[change.sec]:
            raise ValueError(
                "unknown policy type '%s' in section '%s'"
                % (change.ptype, change.sec)
            )
        assertion = model[change.sec][change.ptype]
        expected = len(assertion.tokens)
        if change.sec == "g" and assertion.params_tokens:
            valid = len(change.rule) in (
                expected,
                expected + len(assertion.params_tokens),
            )
        else:
            valid = len(change.rule) == expected
        if not valid:
            raise ValueError(
                "rule %r does not match the arity of '%s'" % (list(change.rule), change.ptype)
            )
        if not all(isinstance(value, str) for value in change.rule):
            raise ValueError("policy rule values must be strings")

    def _verify(self, changes):
        model = self.enforcer.get_model()

        if getattr(self.enforcer, "cond_rm_map", None):
            raise UnsupportedModelError(
                "conditional (temporal) role managers are not supported by "
                "scoped verification"
            )

        # 1. validate and simulate the whole batch on an in-memory copy.
        for change in changes:
            self._validate_change(model, change)

        candidate_model = copy.deepcopy(model)
        for change in changes:
            if change.op == PolicyChange.ADD:
                applied = candidate_model.add_policy(
                    change.sec, change.ptype, list(change.rule)
                )
            else:
                applied = candidate_model.remove_policy(
                    change.sec, change.ptype, list(change.rule)
                )
            if not applied:
                raise ValueError(
                    "change %r does not apply cleanly to the current policy; "
                    "the whole batch is rejected" % (change,)
                )

        # 2. build a throwaway enforcer mirroring the post-batch state.
        candidate = Enforcer(candidate_model)
        for ptype, rm in self.enforcer.rm_map.items():
            if ptype not in candidate.rm_map:
                continue
            if getattr(rm, "matching_func", None) is not None:
                candidate.rm_map[ptype].add_matching_func(rm.matching_func)
            if getattr(rm, "domain_matching_func", None) is not None:
                candidate.rm_map[ptype].add_domain_matching_func(
                    rm.domain_matching_func
                )
        if candidate.rm_map:
            candidate_model.build_role_links(candidate.rm_map)
        self._cache_expressions(candidate)

        # 3. static analysis of every matcher in the model.
        contexts = self._contexts(candidate_model)
        analyses = {}
        for mtype, rtype, ptype, _ in contexts:
            r_tokens = candidate_model["r"][rtype].tokens
            p_tokens = candidate_model["p"][ptype].tokens
            g_names = (
                list(candidate_model["g"].keys()) if "g" in candidate_model.keys() else []
            )
            analysis = _analyze_matcher(
                candidate_model["m"][mtype].value, r_tokens, p_tokens, g_names
            )
            if analysis.error:
                raise UnsupportedModelError(
                    "cannot verify batch against matcher '%s': %s"
                    % (mtype, analysis.error)
                )
            analyses[mtype] = analysis
            for token in r_tokens:
                # fail early when the scope leaves a request attribute undefined
                self.scope.domain_for(self._attr_name(rtype, token))

        # 4. enumeration universe: every value the candidate (or current)
        # state can possibly compare a request attribute against.
        universe = set()
        for state in (model, candidate_model):
            for sec in ("p", "g"):
                if sec not in state.keys():
                    continue
                for assertion in state[sec].values():
                    for rule in assertion.policy:
                        universe.update(rule)
        for analysis in analyses.values():
            universe.update(
                c for c in analysis.constants if isinstance(c, str)
            )
        for mtype, rtype, _, _ in contexts:
            for token in candidate_model["r"][rtype].tokens:
                domain = self.scope.domain_for(self._attr_name(rtype, token))
                if domain is not None:
                    universe.update(domain)

        # 5. pattern provability: every non-literal pattern must target an
        # unrestricted dimension, otherwise containment cannot be proven.
        unprovable = []
        for mtype, _, ptype, _ in contexts:
            analysis = analyses[mtype]
            p_assertion = candidate_model["p"][ptype]
            for func, r_token, source in analysis.pattern_usages:
                attr = self._attr_name(rtype, r_token)
                domain = self.scope.domain_for(attr)
                if source[0] == "const":
                    values = [source[1]]
                else:
                    idx = p_assertion.tokens.index(source[1])
                    values = [
                        rule[idx] for rule in p_assertion.policy if len(rule) > idx
                    ]
                for value in values:
                    if isinstance(value, str):
                        universe.update(_pattern_probes(value))
                    if _is_literal_pattern(func, value):
                        continue
                    if domain is None:
                        continue
                    unprovable.append((func, value, attr))

        # 6. role parents in the candidate state (per grouping function).
        role_parents = {}
        if "g" in candidate_model.keys():
            for gtype, assertion in candidate_model["g"].items():
                role_parents[gtype] = {
                    rule[1] for rule in assertion.policy if len(rule) >= 2
                }

        # 7. enumerate the effective authorization of both states and check
        # that every newly granted request stays inside the scope.
        checked = 0
        for mtype, rtype, ptype, etype in contexts:
            r_tokens = candidate_model["r"][rtype].tokens
            attrs = [self._attr_name(rtype, token) for token in r_tokens]
            dim_universes = []
            for index, attr in enumerate(attrs):
                domain = self.scope.domain_for(attr)
                sentinel = "\x00scoped-sentinel-%d\x00" % index
                while domain is not None and sentinel in domain:
                    sentinel += "x"
                dim_universes.append(universe | {sentinel})
            space = 1
            for dim in dim_universes:
                space *= len(dim)
            checked += space
            if checked > self.max_checks:
                raise UnsupportedModelError(
                    "cannot verify batch: enumeration space (%d requests) "
                    "exceeds max_checks=%d" % (checked, self.max_checks)
                )

            context = EnforceContext(rtype, ptype, etype, mtype)
            analysis = analyses[mtype]
            for combo in itertools.product(*dim_universes):
                if not candidate.enforce_ex(context, *combo)[0]:
                    continue
                if self.enforcer.enforce_ex(context, *combo)[0]:
                    continue
                # the candidate state newly grants this request
                offender = None
                for index, (attr, value) in enumerate(zip(attrs, combo)):
                    if self.scope.contains(attr, value):
                        continue
                    # permissions granted to a role are checked through the
                    # members inheriting them, not through the role itself
                    g_func = analysis.role_attrs.get(r_tokens[index])
                    if g_func is not None and value in role_parents.get(g_func, ()):
                        continue
                    offender = (attr, value)
                    break
                if offender is not None:
                    raise ScopeViolationError(
                        "batch would newly grant %s=%r outside the "
                        "administrator's manageable scope (request: %s)"
                        % (offender[0], offender[1], ", ".join(combo)),
                        witness=combo,
                    )

        # 8. no concrete violation was found, but some patterns could not be
        # proven to stay inside their finite domain: reject conservatively.
        if unprovable:
            func, value, attr = unprovable[0]
            raise UnsupportedModelError(
                "cannot prove that pattern %r (%s) for attribute '%s' stays "
                "within the finite manageable domain; use explicit values or "
                "declare the dimension unrestricted" % (value, func, attr)
            )

        return True

    @staticmethod
    def _cache_expressions(enforcer):
        # enforce_ex re-parses the matcher on every call; the throwaway
        # candidate enforcer is immutable during verification, so caching
        # the parsed expression is safe and speeds enumeration up a lot.
        cache = {}
        base = getattr(Enforcer._get_expression, "__func__", Enforcer._get_expression)

        def cached_get_expression(expr, functions=None):
            if expr not in cache:
                cache[expr] = base(expr, functions)
            return cache[expr]

        enforcer._get_expression = cached_get_expression

    @staticmethod
    def _contexts(model):
        if "m" not in model.keys():
            raise UnsupportedModelError("model has no matcher section")
        contexts = []
        for mtype in model["m"]:
            suffix = mtype[1:]
            rtype, ptype, etype = "r" + suffix, "p" + suffix, "e" + suffix
            missing = [
                key
                for sec, key in (("r", rtype), ("p", ptype), ("e", etype))
                if sec not in model.keys() or key not in model[sec]
            ]
            if missing:
                raise UnsupportedModelError(
                    "model is missing definitions for: %s" % ", ".join(missing)
                )
            contexts.append((mtype, rtype, ptype, etype))
        return contexts

    @staticmethod
    def _attr_name(rtype, token):
        prefix = rtype + "_"
        if token.startswith(prefix):
            return token[len(prefix):]
        return token


def apply_scoped_changes(enforcer, scope, changes, max_checks=200000):
    """convenience wrapper: verifies and applies a batch of PolicyChange
    objects on behalf of a delegated administrator."""
    return ScopedPolicyManager(enforcer, scope, max_checks=max_checks).apply(changes)
