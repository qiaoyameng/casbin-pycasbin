import copy
import re

from casbin.enforcer import Enforcer

__all__ = [
    "GrantScope",
    "PolicyChange",
    "RestrictedManagementError",
    "InvalidChangeError",
    "UnsupportedModelError",
    "OutOfScopeError",
    "apply_restricted_batch",
]

# Built-in matcher functions whose matched language can be enumerated with
# generated witness strings. Anything outside this list makes the containment
# proof un-decidable for this module, so the batch is rejected instead.
_SUPPORTED_MATCHER_FUNCTIONS = {"keyMatch", "keyMatch2", "keyMatch3"}

# Python-level keywords that may appear in a matcher expression and are not
# policy attribute references.
_MATCHER_KEYWORDS = {"and", "or", "not", "in", "if", "else", "True", "False"}

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_FUNCTION_CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_ATTRIBUTE_ACCESS_RE = re.compile(r"[A-Za-z0-9_]\.[A-Za-z_]")
_KEYMATCH_PARAM_RE = re.compile(r":[^/]*")

_WITNESS_TOKEN = "__casbin_restricted_witness__"

DEFAULT_MAX_REQUESTS = 10000


class RestrictedManagementError(Exception):
    """Base error for the restricted management entry point."""


class InvalidChangeError(RestrictedManagementError):
    """A proposed change is malformed or conflicts with the current policy."""


class UnsupportedModelError(RestrictedManagementError):
    """The model uses features for which containment cannot be proven."""


class OutOfScopeError(RestrictedManagementError):
    """The batch would expand effective authorization beyond the grant scope.

    Carries the first out-of-scope request found in ``request`` as a
    (sub, obj, act) tuple.
    """

    def __init__(self, request):
        self.request = tuple(request)
        super().__init__(
            "proposed batch expands effective authorization beyond the grantable scope; "
            "first out-of-scope request: sub={!r}, obj={!r}, act={!r}".format(*self.request)
        )


class GrantScope:
    """The finite set of requests a restricted administrator may grant.

    The grantable set is the cartesian product of explicit subject, object
    and action lists. Anything the candidate policy would allow outside this
    product is rejected.
    """

    def __init__(self, subjects, objects, actions):
        for name, values in (("subjects", subjects), ("objects", objects), ("actions", actions)):
            if not all(isinstance(v, str) for v in values):
                raise ValueError("scope {} must be an iterable of strings".format(name))
        self.subjects = frozenset(subjects)
        self.objects = frozenset(objects)
        self.actions = frozenset(actions)

    def contains(self, sub, obj, act):
        return sub in self.subjects and obj in self.objects and act in self.actions

    def __repr__(self):
        return "GrantScope(subjects={!r}, objects={!r}, actions={!r})".format(
            sorted(self.subjects), sorted(self.objects), sorted(self.actions)
        )


class PolicyChange:
    """A single proposed modification: add or remove one p/g rule."""

    ADD = "add"
    REMOVE = "remove"

    def __init__(self, op, sec, ptype, rule):
        if op not in (self.ADD, self.REMOVE):
            raise InvalidChangeError("invalid change op {!r}; expected 'add' or 'remove'".format(op))
        if sec not in ("p", "g"):
            raise InvalidChangeError("invalid change sec {!r}; expected 'p' or 'g'".format(sec))
        rule = list(rule)
        if not rule or not all(isinstance(v, str) for v in rule):
            raise InvalidChangeError("change rule must be a non-empty list of strings")
        self.op = op
        self.sec = sec
        self.ptype = ptype
        self.rule = rule

    def __repr__(self):
        return "PolicyChange(op={!r}, sec={!r}, ptype={!r}, rule={!r})".format(
            self.op, self.sec, self.ptype, self.rule
        )


def _normalize_change(change):
    if isinstance(change, PolicyChange):
        return change
    if isinstance(change, (tuple, list)):
        if len(change) == 4:
            return PolicyChange(change[0], change[1], change[2], change[3])
        if len(change) == 3:
            return PolicyChange(change[0], change[1], change[1], change[2])
    raise InvalidChangeError(
        "invalid change {!r}; expected PolicyChange, (op, sec, ptype, rule) or (op, sec, rule)".format(change)
    )


def _check_supported(enforcer):
    """Rejects models whose effective authorization cannot be enumerated soundly."""
    model = enforcer.model

    if not getattr(enforcer, "enabled", True):
        raise UnsupportedModelError("enforcer is disabled; cannot verify a disabled enforcer")

    if "r" not in model.keys() or "p" not in model.keys():
        raise UnsupportedModelError("model has no request/policy definition")
    if len(model["r"]) != 1 or len(model["p"]) != 1:
        raise UnsupportedModelError("multiple request/policy definitions are not supported")

    r_tokens = model["r"]["r"].tokens
    p_tokens = model["p"]["p"].tokens
    if r_tokens != ["r_sub", "r_obj", "r_act"]:
        raise UnsupportedModelError(
            "request definition must be 'r = sub, obj, act', got {}".format(", ".join(r_tokens))
        )
    if p_tokens[:3] != ["p_sub", "p_obj", "p_act"]:
        raise UnsupportedModelError(
            "policy definition must start with 'p = sub, obj, act', got {}".format(", ".join(p_tokens))
        )

    matcher = model["m"]["m"].value
    if _ATTRIBUTE_ACCESS_RE.search(matcher):
        raise UnsupportedModelError(
            "matcher uses nested attribute access (ABAC); cannot prove containment: {}".format(matcher)
        )

    g_functions = set(model["g"].keys()) if "g" in model.keys() else set()
    for func in _FUNCTION_CALL_RE.findall(matcher):
        if func in g_functions or func in _SUPPORTED_MATCHER_FUNCTIONS:
            continue
        raise UnsupportedModelError(
            "matcher function {!r} is not supported; supported functions: {}".format(
                func, sorted(_SUPPORTED_MATCHER_FUNCTIONS | g_functions)
            )
        )

    allowed_names = set(r_tokens) | set(p_tokens) | _MATCHER_KEYWORDS
    for name in _IDENTIFIER_RE.findall(matcher):
        if name in allowed_names or name in g_functions or name in _SUPPORTED_MATCHER_FUNCTIONS:
            continue
        raise UnsupportedModelError("matcher references unsupported name {!r}".format(name))

    for rm in getattr(enforcer, "rm_map", {}).values():
        if getattr(rm, "matching_func", None) is not None or getattr(rm, "domain_matching_func", None) is not None:
            raise UnsupportedModelError(
                "role manager pattern matching functions are not supported; cannot prove containment"
            )


def _expected_rule_arity(model, sec, ptype):
    assertion = model[sec][ptype]
    if sec == "p":
        return len(assertion.tokens)
    return assertion.value.count("_")


def _apply_change_to_model(model, change):
    if change.sec not in model.keys() or change.ptype not in model[change.sec]:
        raise InvalidChangeError("unknown policy type {}::{}".format(change.sec, change.ptype))

    expected = _expected_rule_arity(model, change.sec, change.ptype)
    if len(change.rule) != expected:
        raise InvalidChangeError(
            "rule {} has arity {}, expected {} for {}::{}".format(
                change.rule, len(change.rule), expected, change.sec, change.ptype
            )
        )

    exists = model.has_policy(change.sec, change.ptype, change.rule)
    if change.op == PolicyChange.ADD:
        if exists:
            raise InvalidChangeError("rule already exists: {}".format(change.rule))
        model.add_policy(change.sec, change.ptype, change.rule)
    else:
        if not exists:
            raise InvalidChangeError("rule does not exist: {}".format(change.rule))
        model.remove_policy(change.sec, change.ptype, change.rule)


def _build_candidate_enforcer(enforcer, changes):
    """Returns a fresh in-memory enforcer reflecting the proposed batch."""
    model = copy.deepcopy(enforcer.model)
    for change in changes:
        _apply_change_to_model(model, change)

    candidate = Enforcer(model)
    candidate.build_role_links()
    if len(candidate.cond_rm_map) != 0:
        model.build_conditional_role_links(candidate.cond_rm_map)
    return candidate


def _witnesses_for_value(value, token):
    """Generates strings that built-in matchers would match beyond ``value`` itself.

    The enforcer is used as the oracle: a witness only proves a violation if
    the candidate model actually allows a request containing it, so
    over-generating is safe and under-generating is what we must avoid for the
    supported matchers (exact match, keyMatch, keyMatch2, keyMatch3).
    """
    witnesses = {value + token, value + "/" + token}
    if "*" in value:
        prefix = value[: value.index("*")]
        witnesses.add(prefix + token)
        witnesses.add(prefix + token + "/" + token)
    if ":" in value:
        witnesses.add(_KEYMATCH_PARAM_RE.sub(token, value))
    return witnesses


def _build_universe(current_model, candidate_model, scope):
    subjects = set(scope.subjects)
    objects = set(scope.objects)
    actions = set(scope.actions)
    buckets = (subjects, objects, actions)

    token = _WITNESS_TOKEN
    scope_values = subjects | objects | actions
    while any(token in v for v in scope_values):
        token += "x"

    for model in (current_model, candidate_model):
        for ptype in model["p"]:
            for rule in model["p"][ptype].policy:
                for index in range(3):
                    buckets[index].add(rule[index])
                    buckets[index].update(_witnesses_for_value(rule[index], token))
        if "g" in model.keys():
            for gtype in model["g"]:
                for rule in model["g"][gtype].policy:
                    subjects.update(rule)

    return subjects, objects, actions


def _allowed_requests(enforcer, subjects, objects, actions):
    allowed = set()
    for sub in subjects:
        for obj in objects:
            for act in actions:
                if enforcer.enforce(sub, obj, act):
                    allowed.add((sub, obj, act))
    return allowed


def _apply_changes(enforcer, changes):
    """Applies a validated batch to the live enforcer (and its adapter)."""
    for change in changes:
        if change.op == PolicyChange.ADD and change.sec == "p":
            applied = enforcer.add_named_policy(change.ptype, *change.rule)
        elif change.op == PolicyChange.ADD:
            applied = enforcer.add_named_grouping_policy(change.ptype, *change.rule)
        elif change.sec == "p":
            applied = enforcer.remove_named_policy(change.ptype, *change.rule)
        else:
            applied = enforcer.remove_named_grouping_policy(change.ptype, *change.rule)
        if not applied:
            raise RestrictedManagementError(
                "enforcer refused to apply validated change {!r}; the batch may be partially applied".format(change)
            )


def apply_restricted_batch(enforcer, scope, changes, max_requests=DEFAULT_MAX_REQUESTS):
    """Validates a batch of policy changes against a grant scope, then applies it.

    The whole batch is verified before anything is written to the enforcer or
    its adapter: the proposed changes are applied to an in-memory copy of the
    model, and the effective authorization delta (requests allowed by the
    candidate model but not by the current one) is computed by exhaustive
    enforcement over a finite request universe. The universe covers every
    subject/object/action mentioned in the policy, the grouping rules and the
    scope, plus generated witness strings that stand in for the infinite
    languages of the supported built-in matchers (keyMatch, keyMatch2,
    keyMatch3). Role inheritance, wildcards and deny removal are all accounted
    for because the real enforcer evaluates both models.

    Every newly allowed request must lie inside ``scope``; otherwise an
    OutOfScopeError carrying one offending request is raised and nothing is
    applied. Models using matchers or role-manager features for which
    containment cannot be proven are rejected with UnsupportedModelError.
    Returns True when the batch was applied.
    """
    if not isinstance(scope, GrantScope):
        scope = GrantScope(*scope)
    changes = [_normalize_change(change) for change in changes]
    if not changes:
        return True

    _check_supported(enforcer)
    candidate = _build_candidate_enforcer(enforcer, changes)

    subjects, objects, actions = _build_universe(enforcer.model, candidate.model, scope)
    total = len(subjects) * len(objects) * len(actions)
    if total > max_requests:
        raise UnsupportedModelError(
            "request universe too large to verify exhaustively ({} requests > limit {})".format(total, max_requests)
        )

    current_allowed = _allowed_requests(enforcer, subjects, objects, actions)
    candidate_allowed = _allowed_requests(candidate, subjects, objects, actions)

    for request in sorted(candidate_allowed - current_allowed):
        if not scope.contains(*request):
            raise OutOfScopeError(request)

    _apply_changes(enforcer, changes)
    return True
