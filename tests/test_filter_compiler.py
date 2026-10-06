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

import os
from types import SimpleNamespace
from unittest import TestCase

import casbin
from casbin.filter_compiler import (
    And,
    Attr,
    Compare,
    CompileError,
    Const,
    In,
    Not,
    Or,
    interpret,
    node_from_dict,
)


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


def new_enforcer(model_text, policies=(), grouping_policies=()):
    m = casbin.Model()
    m.load_model_from_text(model_text)
    e = casbin.Enforcer(m)
    for policy in policies:
        e.add_policy(*policy)
    for grouping_policy in grouping_policies:
        e.add_grouping_policy(*grouping_policy)
    return e


class TestFilterCompiler(TestCase):
    def assert_parity(self, e, tree, resources, request):
        """request maps token name -> fixed value or None for the symbolic one."""
        for resource in resources:
            attrs = {name: resource for name, value in request.items() if value is None}
            rvals = [request[name] if request[name] is not None else resource for name in request]
            expected = e.enforce(*rvals)
            actual = interpret(tree, attrs)
            self.assertEqual(
                expected,
                actual,
                f"mismatch for resource {resource!r}: enforce={expected}, interpret={actual}",
            )

    def test_allow_and_deny_parity(self):
        e = casbin.Enforcer(
            get_examples("rbac_with_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        resources = ["data1", "data2", "data3"]
        for act in ("read", "write"):
            tree = e.compile_filter(sub="alice", act=act)
            self.assert_parity(
                e, tree, resources, {"sub": "alice", "obj": None, "act": act}
            )

        # alice is allowed to write data2 through the data2_admin role,
        # but the explicit deny rule must still win.
        self.assertFalse(e.enforce("alice", "data2", "write"))
        tree = e.compile_filter(sub="alice", act="write")
        self.assertFalse(interpret(tree, {"obj": "data2"}))
        self.assertTrue(interpret(tree, {"obj": "data1"}) is False)  # no allow rule
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(interpret(e.compile_filter(sub="alice", act="read"), {"obj": "data2"}))

    def test_allow_override_parity(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        resources = ["data1", "data2", "data3"]
        for sub in ("alice", "bob", "eve"):
            for act in ("read", "write"):
                tree = e.compile_filter(sub=sub, act=act)
                self.assert_parity(e, tree, resources, {"sub": sub, "obj": None, "act": act})

    def test_deny_override_parity(self):
        e = new_enforcer(
            """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act, eft
[policy_effect]
e = !some(where (p_eft == deny))
[matchers]
m = r_sub == p_sub && r_obj == p_obj && r_act == p_act
""",
            policies=[("alice", "data1", "read", "deny")],
        )
        tree = e.compile_filter(sub="alice", act="read")
        self.assertIsInstance(tree, Not)
        self.assert_parity(
            e,
            tree,
            ["data1", "data2"],
            {"sub": "alice", "obj": None, "act": "read"},
        )

    def test_in_operator(self):
        e = new_enforcer(
            """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj
[policy_effect]
e = some(where (p_eft == allow))
[matchers]
m = r_sub == p_sub && r_obj == p_obj && r_act in ("read", "write")
""",
            policies=[("alice", "data1")],
        )
        tree = e.compile_filter(sub="alice")
        self.assertTrue(any(isinstance(node, In) for node in self._walk(tree)))
        for obj in ("data1", "data2"):
            for act in ("read", "write", "delete"):
                self.assertEqual(
                    e.enforce("alice", obj, act),
                    interpret(tree, {"obj": obj, "act": act}),
                )

    def test_abac_attribute_comparison(self):
        e = new_enforcer(
            """
[request_definition]
r = sub, obj, act
[policy_definition]
p = act
[policy_effect]
e = some(where (p_eft == allow))
[matchers]
m = r_obj.Owner == r_sub.Name && r_act == p_act
""",
            policies=[("read",)],
        )
        alice = SimpleNamespace(Name="alice")
        tree = e.compile_filter(sub=alice, act="read")
        self.assertEqual(tree, Compare("==", Attr(("obj", "Owner")), Const("alice")))
        resources = [SimpleNamespace(Owner="alice"), SimpleNamespace(Owner="bob")]
        for resource in resources:
            self.assertEqual(
                e.enforce(alice, resource, "read"),
                interpret(tree, {"obj": resource}),
            )

    def test_tree_keeps_attributes_and_constants_apart(self):
        e = casbin.Enforcer(
            get_examples("rbac_with_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        tree = e.compile_filter(sub="alice", act="write")
        self.assertIsInstance(tree, And)
        for node in self._walk(tree):
            if isinstance(node, Compare):
                for operand in (node.left, node.right):
                    self.assertIsInstance(operand, (Attr, Const))
        # the tree is data: it round-trips through a plain dict form
        self.assertEqual(node_from_dict(tree.to_dict()), tree)

    def test_keymatch_is_not_symbolizable(self):
        e = casbin.Enforcer(
            get_examples("keymatch_model.conf"),
            get_examples("keymatch_policy.csv"),
        )
        with self.assertRaises(CompileError) as ctx:
            e.compile_filter(sub="alice", act="read")
        self.assertIn("keyMatch", str(ctx.exception))

    def test_eval_is_not_symbolizable(self):
        e = casbin.Enforcer(get_examples("abac_rule_model.conf"))
        e.add_policy("read_rule", "r_obj == 'data1'")
        with self.assertRaises(CompileError) as ctx:
            e.compile_filter(sub="alice", act="read")
        self.assertIn("eval()", str(ctx.exception))

    def test_priority_effect_is_not_supported(self):
        e = casbin.Enforcer(
            get_examples("priority_model.conf"),
            get_examples("priority_policy.csv"),
        )
        with self.assertRaises(CompileError):
            e.compile_filter(sub="alice", act="read")

    def test_empty_policy(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("empty_policy.csv"),
        )
        tree = e.compile_filter(sub="alice", act="read")
        self.assertEqual(tree, Const(False))
        self.assertFalse(interpret(tree, {"obj": "data1"}))
        self.assertEqual(e.enforce("alice", "data1", "read"), False)

    def _walk(self, node):
        yield node
        for child in getattr(node, "children", ()) or ():
            yield from self._walk(child)
        for attr in ("child", "left", "right", "item"):
            sub = getattr(node, attr, None)
            if sub is not None:
                yield from self._walk(sub)
