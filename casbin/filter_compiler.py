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

"""Partial evaluation of a Casbin matcher into a filter expression tree.

Given an enforcer, a fixed set of request values (typically the user and the
action), :func:`compile_filter` symbolically evaluates the model matcher against
every policy rule and folds the result into a single boolean expression tree
over the remaining (resource) request attributes.

The tree is *data*, not SQL: attributes (:class:`Attr`) and constants
(:class:`Const`) are kept in separate nodes so a data layer can translate it
into whatever query language it speaks.  A reference interpreter,
:func:`interpret`, evaluates the tree against in-memory resources.

Anything that cannot be symbolized (custom matching functions applied to
resource attributes, ``eval()`` rules, priority effects, ...) raises
:class:`CompileError` pointing at the offending construct.  It is never
silently relaxed to ``true``.
"""

import ast
import operator
import re
from collections.abc import Mapping

from casbin.constant.constants import (
    ALLOW_OVERRIDE_EFFECT,
    DENY_OVERRIDE_EFFECT,
    ALLOW_AND_DENY_EFFECT,
)
from casbin.util import util, generate_g_function, generate_conditional_g_function


class CompileError(RuntimeError):
    """raised when a matcher cannot be compiled into a filter expression tree."""

    pass


class Node:
    """base class of the filter expression tree."""

    def to_dict(self):
        raise NotImplementedError

    def __eq__(self, other):
        return type(self) is type(other) and self.__dict__ == other.__dict__

    def __hash__(self):
        return hash(repr(self))


class Const(Node):
    """a constant value known at compile time."""

    def __init__(self, value):
        self.value = value

    def to_dict(self):
        return {"type": "const", "value": self.value}

    def __repr__(self):
        return f"Const({self.value!r})"


class Attr(Node):
    """a resource attribute left symbolic, e.g. Attr(("obj",)) or Attr(("obj", "owner"))."""

    def __init__(self, path):
        self.path = tuple(path)

    def to_dict(self):
        return {"type": "attr", "path": list(self.path)}

    def __repr__(self):
        return f"Attr({'.'.join(self.path)})"


class Compare(Node):
    """a comparison between two operands; op is one of ==, !=, <, <=, >, >=."""

    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

    def to_dict(self):
        return {
            "type": "compare",
            "op": self.op,
            "left": self.left.to_dict(),
            "right": self.right.to_dict(),
        }

    def __repr__(self):
        return f"Compare({self.left!r} {self.op} {self.right!r})"


class In(Node):
    """membership of an attribute in a finite, precomputed set of constants."""

    def __init__(self, item, options):
        self.item = item
        self.options = tuple(options)

    def to_dict(self):
        return {"type": "in", "item": self.item.to_dict(), "options": list(self.options)}

    def __repr__(self):
        return f"In({self.item!r}, {list(self.options)!r})"


class And(Node):
    def __init__(self, children):
        self.children = tuple(children)

    def to_dict(self):
        return {"type": "and", "children": [c.to_dict() for c in self.children]}

    def __repr__(self):
        return f"And({', '.join(repr(c) for c in self.children)})"


class Or(Node):
    def __init__(self, children):
        self.children = tuple(children)

    def to_dict(self):
        return {"type": "or", "children": [c.to_dict() for c in self.children]}

    def __repr__(self):
        return f"Or({', '.join(repr(c) for c in self.children)})"


class Not(Node):
    def __init__(self, child):
        self.child = child

    def to_dict(self):
        return {"type": "not", "child": self.child.to_dict()}

    def __repr__(self):
        return f"Not({self.child!r})"


_NODE_TYPES = {
    "const": lambda d: Const(d["value"]),
    "attr": lambda d: Attr(d["path"]),
    "compare": lambda d: Compare(d["op"], node_from_dict(d["left"]), node_from_dict(d["right"])),
    "in": lambda d: In(node_from_dict(d["item"]), d["options"]),
    "and": lambda d: And([node_from_dict(c) for c in d["children"]]),
    "or": lambda d: Or([node_from_dict(c) for c in d["children"]]),
    "not": lambda d: Not(node_from_dict(d["child"])),
}


def node_from_dict(d):
    """rebuilds an expression tree from its :meth:`Node.to_dict` form."""
    kind = d["type"]
    if kind not in _NODE_TYPES:
        raise ValueError(f"unknown node type: {kind!r}")
    return _NODE_TYPES[kind](d)


_COMPARE_OPS = {
    "==": operator.eq,
    "!=": operator.ne,
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
}

_AST_COMPARE_OPS = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
}

_AST_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
}


def _resolve(node, attributes):
    """resolves a value-producing node (Const/Attr) against a resource."""
    if isinstance(node, Const):
        return node.value
    if isinstance(node, Attr):
        value = attributes[node.path[0]]
        for part in node.path[1:]:
            if isinstance(value, Mapping):
                value = value[part]
            else:
                value = getattr(value, part)
        return value
    raise TypeError(f"not a value node: {node!r}")


def interpret(node, attributes):
    """interprets a compiled filter tree against one in-memory resource.

    ``attributes`` maps request token names (e.g. ``"obj"``) to the resource's
    values; nested values may be mappings or objects.
    """
    if isinstance(node, Const):
        return bool(node.value)
    if isinstance(node, Compare):
        left = _resolve(node.left, attributes)
        right = _resolve(node.right, attributes)
        return bool(_COMPARE_OPS[node.op](left, right))
    if isinstance(node, In):
        return _resolve(node.item, attributes) in node.options
    if isinstance(node, And):
        return all(interpret(c, attributes) for c in node.children)
    if isinstance(node, Or):
        return any(interpret(c, attributes) for c in node.children)
    if isinstance(node, Not):
        return not interpret(node.child, attributes)
    raise TypeError(f"not a filter node: {node!r}")


def _normalize_matcher(expr):
    expr = expr.replace("&&", "and")
    expr = expr.replace("||", "or")
    expr = re.sub(r"!(?!=)", "not ", expr)
    return expr


def _and(children):
    kept = []
    for child in children:
        if isinstance(child, Const):
            if not child.value:
                return Const(False)
            continue
        kept.append(child)
    if not kept:
        return Const(True)
    if len(kept) == 1:
        return kept[0]
    return And(kept)


def _or(children):
    kept = []
    for child in children:
        if isinstance(child, Const):
            if child.value:
                return Const(True)
            continue
        kept.append(child)
    if not kept:
        return Const(False)
    if len(kept) == 1:
        return kept[0]
    return Or(kept)


def _not(child):
    if isinstance(child, Const):
        return Const(not child.value)
    return Not(child)


class _PartialEvaluator(ast.NodeVisitor):
    """folds a matcher AST into a filter tree given an env of Const/Attr leaves."""

    def __init__(self, env, functions, matcher):
        self.env = env
        self.functions = functions
        self.matcher = matcher

    def error(self, message):
        return CompileError(f"cannot compile matcher {self.matcher!r}: {message}")

    def visit(self, node):
        method = "visit_" + node.__class__.__name__
        visitor = getattr(self, method, None)
        if visitor is None:
            raise self.error(f"unsupported syntax {node.__class__.__name__}")
        return visitor(node)

    def visit_Expression(self, node):
        return self.visit(node.body)

    def visit_Constant(self, node):
        return Const(node.value)

    def visit_Name(self, node):
        if node.id in self.env:
            return self.env[node.id]
        raise self.error(f"unknown name {node.id!r}")

    def visit_Attribute(self, node):
        base = self.visit(node.value)
        if isinstance(base, Const):
            try:
                return Const(getattr(base.value, node.attr))
            except AttributeError:
                raise self.error(f"unknown attribute {node.attr!r}")
        if isinstance(base, Attr):
            return Attr(base.path + (node.attr,))
        raise self.error(f"cannot access attribute {node.attr!r}")

    def visit_Subscript(self, node):
        base = self.visit(node.value)
        index = self.visit(node.slice)
        if isinstance(base, Const) and isinstance(index, Const):
            return Const(base.value[index.value])
        raise self.error("subscript over resource attributes is not supported")

    def visit_Tuple(self, node):
        return self._visit_sequence(node.elts, tuple)

    def visit_List(self, node):
        return self._visit_sequence(node.elts, list)

    def visit_Set(self, node):
        return self._visit_sequence(node.elts, set)

    def _visit_sequence(self, elts, constructor):
        values = []
        for elt in elts:
            value = self.visit(elt)
            if not isinstance(value, Const):
                raise self.error("collection literals must be constant")
            values.append(value.value)
        return Const(constructor(values))

    def visit_BoolOp(self, node):
        children = [self.visit(value) for value in node.values]
        if isinstance(node.op, ast.And):
            return _and(children)
        return _or(children)

    def visit_UnaryOp(self, node):
        operand = self.visit(node.operand)
        if isinstance(node.op, ast.Not):
            return _not(operand)
        if isinstance(node.op, (ast.UAdd, ast.USub)) and isinstance(operand, Const):
            return Const(+operand.value if isinstance(node.op, ast.UAdd) else -operand.value)
        raise self.error(f"unsupported unary operator {node.op.__class__.__name__}")

    def visit_BinOp(self, node):
        left = self.visit(node.left)
        right = self.visit(node.right)
        op = _AST_BIN_OPS.get(type(node.op))
        if op is not None and isinstance(left, Const) and isinstance(right, Const):
            return Const(op(left.value, right.value))
        raise self.error("arithmetic over resource attributes is not supported")

    def visit_Compare(self, node):
        operands = [self.visit(node.left)] + [self.visit(c) for c in node.comparators]
        parts = []
        for op, left, right in zip(node.ops, operands, operands[1:]):
            parts.append(self._compare(op, left, right))
        return _and(parts)

    def _compare(self, op, left, right):
        if isinstance(op, (ast.In, ast.NotIn)):
            return self._membership(op, left, right)
        symbol = _AST_COMPARE_OPS.get(type(op))
        if symbol is None:
            raise self.error(f"unsupported comparison operator {op.__class__.__name__}")
        if isinstance(left, Const) and isinstance(right, Const):
            return Const(_COMPARE_OPS[symbol](left.value, right.value))
        return Compare(symbol, left, right)

    def _membership(self, op, item, options):
        if isinstance(options, Const) and isinstance(options.value, (tuple, list, set, frozenset)):
            values = tuple(options.value)
        else:
            raise self.error("'in' requires a finite constant set on the right-hand side")
        node = In(item, values) if not isinstance(item, Const) else Const(item.value in values)
        if isinstance(op, ast.NotIn):
            return _not(node)
        return node

    def visit_Call(self, node):
        if not isinstance(node.func, ast.Name):
            raise self.error("only plain function calls are supported")
        name = node.func.id
        if name not in self.functions:
            raise self.error(f"unknown function {name!r}")
        args = [self.visit(arg) for arg in node.args]
        symbolic = [arg for arg in args if not isinstance(arg, Const)]
        if symbolic:
            raise self.error(
                f"function {name!r} cannot be symbolized: it is applied to resource attributes"
            )
        return Const(self.functions[name](*[arg.value for arg in args]))

    def visit_IfExp(self, node):
        raise self.error("conditional expressions are not supported")


def compile_filter(enforcer, fixed, rtype="r", ptype="p", etype="e", mtype="m"):
    """compiles an enforcer's matcher into a filter expression tree.

    ``fixed`` maps request token names (without the ``r_`` prefix, e.g.
    ``{"sub": "alice", "act": "read"}``) to constant values; every remaining
    request token stays symbolic and shows up in the tree as an :class:`Attr`.

    The returned tree already encodes the model's policy effect, including
    deny rules overriding allow rules.  Raises :class:`CompileError` when any
    construct cannot be symbolized.
    """
    model = enforcer.model
    if "m" not in model.keys() or mtype not in model["m"].keys():
        raise RuntimeError("model is undefined")

    exp_string = model["m"][mtype].value
    if util.has_eval(exp_string):
        raise CompileError(f"cannot compile matcher {exp_string!r}: eval() rules are not symbolizable")

    effect = model["e"][etype].value
    if effect not in (ALLOW_OVERRIDE_EFFECT, DENY_OVERRIDE_EFFECT, ALLOW_AND_DENY_EFFECT):
        raise CompileError(f"cannot compile policy effect {effect!r}: ordered effects are not supported")

    r_tokens = model["r"][rtype].tokens
    p_tokens = model["p"][ptype].tokens

    env = {}
    for token in r_tokens:
        name = token[len(rtype) + 1 :] if token.startswith(rtype + "_") else token
        if name in fixed:
            env[token] = Const(fixed[name])
        elif token in fixed:
            env[token] = Const(fixed[token])
        else:
            env[token] = Attr((name,))

    functions = enforcer.fm.get_functions()
    if "g" in model.keys():
        for key, g_ast in model["g"].items():
            if len(enforcer.rm_map) != 0:
                functions[key] = generate_g_function(g_ast.rm)
            if len(enforcer.cond_rm_map) != 0:
                functions[key] = generate_conditional_g_function(g_ast.cond_rm)

    parsed = ast.parse(_normalize_matcher(exp_string).strip()).body[0].value

    policies = model["p"][ptype].policy
    if not policies:
        # mirror enforce(): with no policy the matcher runs once with empty p tokens
        policies = [[""] * len(p_tokens)]

    allow_rules = []
    deny_rules = []
    for pvals in policies:
        if len(p_tokens) != len(pvals):
            raise RuntimeError("invalid policy size")
        rule_env = dict(env)
        rule_env.update({token: Const(value) for token, value in zip(p_tokens, pvals)})

        evaluator = _PartialEvaluator(rule_env, functions, exp_string)
        residual = evaluator.visit(parsed)
        if isinstance(residual, Const) and not residual.value:
            continue

        eft_token = ptype + "_eft"
        eft = rule_env[eft_token].value if eft_token in rule_env else "allow"
        if eft == "allow":
            allow_rules.append(residual)
        elif eft == "deny":
            deny_rules.append(residual)
        # any other effect is indeterminate: the rule never matches

    allow_any = _or(allow_rules)
    deny_any = _or(deny_rules)

    if effect == ALLOW_OVERRIDE_EFFECT:
        return allow_any
    if effect == DENY_OVERRIDE_EFFECT:
        return _not(deny_any)
    return _and([allow_any, _not(deny_any)])
