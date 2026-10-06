from unittest import TestCase

from casbin import Enforcer
from casbin.filter_compiler import Constant, Field, FilterCompileError
from casbin.persist.adapters.string_adapter import StringAdapter


class Resource:
    def __init__(self, **values):
        self.__dict__.update(values)


class TestFilterCompiler(TestCase):
    def make_enforcer(self, model, policy):
        return Enforcer(Enforcer.new_model(text=model), StringAdapter(policy))

    def assert_matches_enforce(self, enforcer, resources, user="alice", action="read"):
        compiled = enforcer.compile_object_filter(user, action)
        for resource in resources:
            self.assertEqual(
                compiled.evaluate(resource),
                enforcer.enforce(user, resource, action),
                resource,
            )

    def test_compiled_filter_matches_enforce_with_deny_override(self):
        model = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act, eft
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
[matchers]
m = g(r.sub, p.sub) && r.act == p.act && (r.obj.owner == p.obj || r.obj.level >= 2) && r.obj.tag in ["public", "shared"]
"""
        policy = """
p, reader, alice, read, allow
p, blocker, carol, read, deny
g, alice, reader
g, alice, blocker
"""
        enforcer = self.make_enforcer(model, policy)
        resources = [
            Resource(owner="alice", level=2, tag="public"),
            Resource(owner="bob", level=3, tag="shared"),
            Resource(owner="carol", level=5, tag="public"),
            Resource(owner="alice", level=1, tag="public"),
            Resource(owner="alice", level=2, tag="private"),
        ]

        self.assert_matches_enforce(enforcer, resources)

        compiled = enforcer.compile_object_filter("alice", "read")
        self.assertIn(Field(("owner",)).path, self.collect_fields(compiled))

    def test_compiled_filter_separates_fields_and_constants(self):
        model = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, min_age, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.act == p.act && r.obj["age"] == p.min_age
"""
        policy = "p, alice, 18, read\n"
        enforcer = self.make_enforcer(model, policy)

        compiled_tree = enforcer.compile_object_filter("alice", "read")
        compiled = compiled_tree.to_dict()
        self.assertEqual(compiled["left"]["type"], "field")
        self.assertEqual(compiled["left"]["path"], ["age"])
        self.assertEqual(compiled["right"], {"type": "constant", "value": "18"})

        self.assertTrue(compiled_tree.evaluate({"age": "18"}))
        self.assertTrue(enforcer.enforce("alice", {"age": "18"}, "read"))
        self.assertFalse(enforcer.enforce("alice", {"age": "17"}, "read"))

    def test_priority_deny_rule_is_respected(self):
        model = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act, eft
[role_definition]
g = _, _
[policy_effect]
e = priority(p.eft) || deny
[matchers]
m = g(r.sub, p.sub) && r.act == p.act && r.obj.team == p.obj
"""
        policy = """
p, blocked, ops, read, deny
p, admin, ops, read, allow
g, alice, admin
g, alice, blocked
"""
        enforcer = self.make_enforcer(model, policy)
        resources = [Resource(team="ops"), Resource(team="sales")]
        self.assert_matches_enforce(enforcer, resources)

    def test_explicit_priority_policy_is_sorted(self):
        model = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = priority, sub, obj, act, eft
[policy_effect]
e = priority(p.eft) || deny
[matchers]
m = r.sub == p.sub && r.act == p.act && r.obj.name == p.obj
"""
        policy = """
p, 1, alice, data, read, allow
p, 0, alice, data, read, deny
"""
        enforcer = self.make_enforcer(model, policy)
        resources = [Resource(name="data"), Resource(name="other")]
        self.assert_matches_enforce(enforcer, resources)

    def test_not_in_and_negation_match_enforce(self):
        model = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act, eft
[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
[matchers]
m = r.sub == p.sub && r.act == p.act && !(r.obj.kind in ["secret"]) && r.obj.state not in ["locked", "archived"]
"""
        policy = """
p, alice, any, read, allow
p, alice, blocked, read, deny
"""
        enforcer = self.make_enforcer(model, policy)
        resources = [
            Resource(kind="normal", state="active"),
            Resource(kind="secret", state="active"),
            Resource(kind="normal", state="locked"),
        ]
        self.assert_matches_enforce(enforcer, resources)

    def test_effect_models_have_equivalent_results(self):
        effects = {
            "allow": "some(where (p.eft == allow))",
            "deny": "!some(where (p.eft == deny))",
            "both": "some(where (p.eft == allow)) && !some(where (p.eft == deny))",
            "priority": "priority(p.eft) || deny",
        }
        resources = [
            Resource(owner="alice", team="ops", level="1", status="ready"),
            Resource(owner="bob", team="ops", level="3", status="ready"),
            Resource(owner="carol", team="ops", level="4", status="frozen"),
            Resource(owner="dave", team="sales", level="2", status="ready"),
        ]

        for name, effect in effects.items():
            with self.subTest(effect=name):
                if name == "priority":
                    policy = """
p, blocker, ops, 3, frozen, read, deny
p, reader, ops, 2, ready, read, allow
"""
                else:
                    policy = """
p, reader, ops, 2, ready, read, allow
p, blocker, ops, 3, frozen, read, deny
"""
                model = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, min_level, status, act, eft
[policy_effect]
e = {effect}
[matchers]
m = (r.sub == p.sub || r.sub == "alice") && r.act == p.act && r.obj.team == p.obj && r.obj.level >= p.min_level && r.obj.status == p.status
""".format(effect=effect)
                enforcer = self.make_enforcer(model, policy)
                self.assert_matches_enforce(enforcer, resources)

    def test_unsymbolizable_custom_function_blocks_compilation(self):
        model = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.act == p.act && custom(r.obj.owner)
"""
        enforcer = self.make_enforcer(model, "p, alice, alice, read\n")
        enforcer.add_function("custom", lambda value: value == "alice")

        with self.assertRaises(FilterCompileError) as context:
            enforcer.compile_object_filter("alice", "read")
        self.assertEqual(context.exception.rule_index, 0)
        self.assertIn("custom", str(context.exception))

    def test_constant_custom_function_is_still_blocked(self):
        model = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.act == p.act && custom(p.obj)
"""
        enforcer = self.make_enforcer(model, "p, alice, alice, read\n")
        enforcer.add_function("custom", lambda value: value == "alice")

        with self.assertRaises(FilterCompileError) as context:
            enforcer.compile_object_filter("alice", "read")
        self.assertIn("custom", str(context.exception))

    def test_eval_rule_blocks_compilation_instead_of_allowing_everything(self):
        model = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub_rule, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = eval(p.sub_rule) && r.obj == p.obj && r.act == p.act
"""
        enforcer = self.make_enforcer(model, 'p, r.sub.age > 18, data1, read\n')

        with self.assertRaises(FilterCompileError) as error:
            enforcer.compile_object_filter("alice", "read")
        self.assertNotIsInstance(error.exception.__class__, Constant)

    def collect_fields(self, node):
        if isinstance(node, Field):
            return [node.path]
        fields = []
        if hasattr(node, "left"):
            fields.extend(self.collect_fields(node.left))
            fields.extend(self.collect_fields(node.right))
        if hasattr(node, "operands"):
            for operand in node.operands:
                fields.extend(self.collect_fields(operand))
        return fields
