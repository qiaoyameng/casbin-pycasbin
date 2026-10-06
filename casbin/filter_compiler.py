import ast
import operator
import re

from casbin.constant.constants import (
    ALLOW_AND_DENY_EFFECT,
    ALLOW_OVERRIDE_EFFECT,
    DENY_OVERRIDE_EFFECT,
    PRIORITY_EFFECT,
    SUBJECT_PRIORITY_EFFECT,
)
from casbin.util import generate_conditional_g_function, generate_g_function


class FilterCompileError(ValueError):
    def __init__(self, message, rule_index=None, source="", node=None):
        self.rule_index = rule_index
        self.source = source
        self.lineno = getattr(node, "lineno", 1)
        self.col_offset = getattr(node, "col_offset", 0)
        super().__init__(message)


class FilterNode:
    type = "node"

    def evaluate(self, resource):
        raise NotImplementedError

    def to_dict(self):
        raise NotImplementedError


class Constant(FilterNode):
    type = "constant"

    def __init__(self, value):
        self.value = value

    def evaluate(self, resource):
        return self.value

    def to_dict(self):
        return {"type": self.type, "value": self.value}


class Field(FilterNode):
    type = "field"

    def __init__(self, path):
        self.path = tuple(path)

    def evaluate(self, resource):
        value = resource
        for key in self.path:
            if isinstance(value, dict):
                value = value[key]
            else:
                value = getattr(value, key)
        return value

    def to_dict(self):
        return {"type": self.type, "path": list(self.path)}


class Comparison(FilterNode):
    type = "comparison"

    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right
        self._operator = {
            "eq": operator.eq,
            "ne": operator.ne,
            "lt": operator.lt,
            "lte": operator.le,
            "gt": operator.gt,
            "gte": operator.ge,
            "in": lambda left, right: left in right,
            "not_in": lambda left, right: left not in right,
        }[op]

    def evaluate(self, resource):
        return self._operator(self.left.evaluate(resource), self.right.evaluate(resource))

    def to_dict(self):
        return {
            "type": self.type,
            "op": self.op,
            "left": self.left.to_dict(),
            "right": self.right.to_dict(),
        }


class Boolean(FilterNode):
    type = "boolean"

    def __init__(self, op, operands):
        self.op = op
        self.operands = operands

    def evaluate(self, resource):
        values = [operand.evaluate(resource) for operand in self.operands]
        if self.op == "and":
            return all(values)
        if self.op == "or":
            return any(values)
        return not values[0]

    def to_dict(self):
        return {"type": self.type, "op": self.op, "operands": [item.to_dict() for item in self.operands]}


TRUE = Constant(True)
FALSE = Constant(False)


def make_bool(op, operands):
    operands = [item for item in operands if item is not None]
    if not operands:
        return TRUE if op == "and" else FALSE
    if len(operands) == 1:
        return operands[0]

    flattened = []
    for operand in operands:
        if isinstance(operand, Boolean) and operand.op == op:
            flattened.extend(operand.operands)
        else:
            flattened.append(operand)

    constants = [item.value for item in flattened if isinstance(item, Constant)]
    symbolic = [item for item in flattened if not isinstance(item, Constant)]
    if op == "and":
        if any(value is False for value in constants):
            return FALSE
    elif any(value is True for value in constants):
        return TRUE

    if not symbolic:
        return TRUE if op == "and" else FALSE
    if len(symbolic) == 1:
        return symbolic[0]
    return Boolean(op, symbolic)


def negate(node):
    if isinstance(node, Constant):
        return Constant(not node.value)
    return Boolean("not", [node])


class _RuleCompiler:
    _MISSING = object()
    comparison_operators = {
        ast.Eq: "eq",
        ast.NotEq: "ne",
        ast.Lt: "lt",
        ast.LtE: "lte",
        ast.Gt: "gt",
        ast.GtE: "gte",
        ast.In: "in",
        ast.NotIn: "not_in",
    }

    def __init__(self, fixed_names, policy_names, role_functions, source):
        self.fixed_names = fixed_names
        self.policy_names = policy_names
        self.role_functions = role_functions
        self.source = source

    def compile(self, node):
        return self._compile(node)

    def _compile(self, node):
        if isinstance(node, ast.BoolOp):
            op = "and" if isinstance(node.op, ast.And) else "or"
            return make_bool(op, [self._compile(item) for item in node.values])

        if isinstance(node, ast.UnaryOp):
            if not isinstance(node.op, ast.Not):
                raise self.error("unsupported unary operator", node)
            return negate(self._compile(node.operand))

        if isinstance(node, ast.Compare):
            return self.compile_compare(node)

        if isinstance(node, ast.Call):
            return self.compile_call(node)

        constant = self.constant_value(node)
        if constant is not self._MISSING:
            return Constant(constant)

        field = self.resource_field(node)
        if field is not None:
            return field

        raise self.error("unsupported expression", node)

    def compile_compare(self, node):
        if len(node.ops) != 1:
            raise self.error("chained comparisons are not supported", node)

        op_type = type(node.ops[0])
        op = self.comparison_operators.get(op_type)
        if op is None:
            raise self.error("unsupported comparison operator", node)

        left = self._compile(node.left)
        right = self._compile(node.comparators[0])
        if isinstance(left, Field) and isinstance(right, Field):
            raise self.error("comparison must compare a resource attribute with a constant", node)
        if isinstance(left, Constant) and isinstance(right, Constant):
            operators = {
                "eq": operator.eq,
                "ne": operator.ne,
                "lt": operator.lt,
                "lte": operator.le,
                "gt": operator.gt,
                "gte": operator.ge,
                "in": lambda item, container: item in container,
                "not_in": lambda item, container: item not in container,
            }
            return Constant(operators[op](left.value, right.value))
        return Comparison(op, left, right)

    def compile_call(self, node):
        if not isinstance(node.func, ast.Name):
            raise self.error("unsupported function call", node)

        name = node.func.id
        if name in self.role_functions:
            args = [self.constant_value(arg) for arg in node.args]
            if any(arg is self._MISSING for arg in args) or node.keywords:
                raise self.error("function {} cannot be symbolized".format(name), node)
            return Constant(self.role_functions[name](*args))

        raise self.error("function {} cannot be symbolized".format(name), node)

    def constant_value(self, node):
        missing = self._MISSING

        if isinstance(node, ast.Name):
            if node.id in self.fixed_names:
                if self.fixed_names[node.id] == "__resource__":
                    return missing
                return self.fixed_names[node.id]
            return self.policy_names.get(node.id, missing)

        if isinstance(node, ast.Attribute):
            parent = self.constant_value(node.value)
            if parent is not missing:
                try:
                    return getattr(parent, node.attr)
                except AttributeError:
                    return missing

        if isinstance(node, ast.Subscript):
            if self.resource_field(node) is not None:
                return missing
            parent = self.constant_value(node.value)
            key = self.constant_value(node.slice)
            if parent is not missing and key is not missing:
                try:
                    return parent[key]
                except (KeyError, IndexError, TypeError):
                    return missing

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = [self.constant_value(item) for item in node.elts]
            if all(value is not missing for value in values):
                if isinstance(node, ast.List):
                    return list(values)
                return list(values)

        if isinstance(node, ast.Dict):
            keys = [self.constant_value(item) for item in node.keys]
            values = [self.constant_value(item) for item in node.values]
            if all(key is not missing for key in keys) and all(value is not missing for value in values):
                return dict(zip(keys, values))

        try:
            return ast.literal_eval(node)
        except (ValueError, SyntaxError):
            return missing

    def resource_field(self, node):
        if isinstance(node, ast.Name):
            if self.fixed_names.get(node.id) == "__resource__":
                return Field(())
            return None

        if isinstance(node, ast.Attribute):
            parent = self.resource_field(node.value)
            if parent is not None:
                return Field(parent.path + (node.attr,))

        if isinstance(node, ast.Subscript):
            parent = self.resource_field(node.value)
            key = self.constant_value(node.slice)
            if parent is not None and isinstance(key, (str, int)):
                return Field(parent.path + (key,))

        return None

    def error(self, message, node):
        return FilterCompileError(message, source=self.source, node=node)


def compile_object_filter(enforcer, user, action):
    rtype, ptype, etype, mtype = "r", "p", "e", "m"
    r_tokens = enforcer.model["r"][rtype].tokens
    p_tokens = enforcer.model["p"][ptype].tokens
    if len(r_tokens) < 2:
        raise FilterCompileError("request model must contain subject and resource")

    token_suffixes = {token[len(rtype) + 1 :]: token for token in r_tokens}
    subject_token = token_suffixes.get("sub")
    resource_token = token_suffixes.get("obj")
    action_token = token_suffixes.get("act")
    if subject_token is None or resource_token is None:
        raise FilterCompileError("request model must contain sub and obj")

    source = enforcer.model["m"][mtype].value
    try:
        tree = ast.parse(normalize_expression(source), mode="eval")
    except SyntaxError as error:
        raise FilterCompileError("invalid matcher expression: {}".format(error.msg), source=source)

    role_functions = {}
    if "g" in enforcer.model.keys():
        for key, assertion in enforcer.model["g"].items():
            if assertion.rm is not None:
                role_functions[key] = generate_g_function(assertion.rm)
            if assertion.cond_rm is not None:
                role_functions[key] = generate_conditional_g_function(assertion.cond_rm)

    fixed_names = {subject_token: user, resource_token: "__resource__"}
    if action_token is not None:
        fixed_names[action_token] = action

    policies = list(enforcer.model["p"][ptype].policy)
    priority_token = ptype + "_priority"
    priority_index = p_tokens.index(priority_token) if priority_token in p_tokens else -1
    if priority_index >= 0:
        policies = sorted(policies, key=lambda policy: policy[priority_index])

    rules = []
    for rule_index, policy in enumerate(policies):
        if len(policy) != len(p_tokens):
            raise FilterCompileError("invalid policy size", rule_index, source)

        policy_names = dict(zip(p_tokens, policy))
        effect = policy_names.get(ptype + "_eft", "allow")
        if effect not in ("allow", "deny"):
            continue

        compiler = _RuleCompiler(fixed_names, policy_names, role_functions, source)
        try:
            condition = compiler.compile(tree.body)
        except FilterCompileError as error:
            error.rule_index = rule_index
            raise

        if isinstance(condition, Constant) and not condition.value:
            continue
        rules.append((effect, condition))

    return combine_rules(enforcer.model["e"][etype].value, rules)


def normalize_expression(expression):
    expression = expression.replace("&&", " and ")
    expression = expression.replace("||", " or ")
    return re.sub(r"!(?!=)", " not ", expression)


def combine_rules(effect_type, rules):
    if effect_type == ALLOW_OVERRIDE_EFFECT:
        return make_bool("or", [condition for effect, condition in rules if effect == "allow"])

    if effect_type == DENY_OVERRIDE_EFFECT:
        return make_bool("and", [negate(condition) for effect, condition in rules if effect == "deny"])

    if effect_type == ALLOW_AND_DENY_EFFECT:
        return make_bool(
            "and",
            [
                make_bool("or", [condition for effect, condition in rules if effect == "allow"]),
                make_bool("and", [negate(condition) for effect, condition in rules if effect == "deny"]),
            ],
        )

    if effect_type in (PRIORITY_EFFECT, SUBJECT_PRIORITY_EFFECT):
        result = FALSE
        for effect, condition in reversed(rules):
            if effect == "allow":
                result = make_bool("or", [condition, result])
            else:
                result = make_bool("and", [negate(condition), result])
        return result

    raise FilterCompileError("unsupported policy effect: {}".format(effect_type))
