# Copyright 2024 The casbin Authors. All Rights Reserved.
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

import pytest

from casbin.relationship import (
    Schema,
    direct,
    computed,
    tuple_userset,
    union,
    intersect,
    difference,
    InvalidSchemaError,
    NegativeRecursionError,
)


class TestSchemaValidation:
    def test_rewrite_must_be_node(self):
        with pytest.raises(InvalidSchemaError):
            Schema({"document": {"viewer": "direct()"}})

    def test_computed_must_reference_known_relation(self):
        with pytest.raises(InvalidSchemaError):
            Schema({"document": {"viewer": computed("nope")}})

    def test_tuple_relation_must_exist(self):
        with pytest.raises(InvalidSchemaError):
            Schema(
                {
                    "folder": {"viewer": direct()},
                    "document": {
                        "viewer": tuple_userset("parent", "viewer"),
                    },
                }
            )


class TestNegativeRecursionRejected:
    def test_direct_self_subtraction(self):
        with pytest.raises(NegativeRecursionError):
            Schema(
                {
                    "document": {
                        "blocked": direct(),
                        "viewer": difference(direct(), [computed("viewer")]),
                    }
                }
            )

    def test_indirect_negative_cycle(self):
        with pytest.raises(NegativeRecursionError):
            Schema(
                {
                    "document": {
                        "viewer": difference(direct(), [computed("x")]),
                        "x": computed("viewer"),
                    }
                }
            )

    def test_two_node_cycle_negative_edge(self):
        with pytest.raises(NegativeRecursionError):
            Schema(
                {
                    "document": {
                        "viewer": computed("x"),
                        "x": difference(direct(), [computed("viewer")]),
                    }
                }
            )

    def test_negative_branch_leaves_scc_and_returns(self):
        with pytest.raises(NegativeRecursionError):
            Schema(
                {
                    "document": {
                        "viewer": union([direct(), computed("x")]),
                        "x": difference(direct(), [computed("y")]),
                        "y": computed("z"),
                        "z": computed("viewer"),
                    }
                }
            )

    def test_positive_self_recursion_is_allowed(self):
        Schema({"folder": {"viewer": union([direct(), computed("viewer")])}})

    def test_positive_mutual_recursion_is_allowed(self):
        Schema(
            {
                "team": {
                    "a": union([direct(), computed("b")]),
                    "b": union([direct(), computed("a")]),
                }
            }
        )

    def test_acyclic_difference_is_allowed(self):
        Schema(
            {
                "document": {
                    "viewer": difference(direct(), [computed("blocked")]),
                    "blocked": direct(),
                }
            }
        )

    def test_subtract_independent_recursive_relation(self):
        # blocked recurses positively on its own relation; subtracting it
        # does not feed viewer back into itself.
        Schema(
            {
                "document": {
                    "viewer": difference(direct(), [computed("blocked")]),
                    "blocked": union([direct(), computed("blocked")]),
                }
            }
        )

    def test_subtract_tuple_userset_accepted_at_definition(self):
        # The target type is data-defined, so no static negative edge exists;
        # runtime data that closes a negative cycle is rejected by the
        # evaluator rather than truncated.
        Schema(
            {
                "folder": {"parent": direct(), "blocked": direct(), "viewer": direct()},
                "document": {
                    "parent": direct(),
                    "viewer": difference(direct(), [tuple_userset("parent", "blocked")]),
                },
            }
        )


class TestSetOperators:
    def test_node_operator_overloads(self):
        from casbin.relationship import Union, Intersect, Difference

        node = direct() | computed("x")
        assert isinstance(node, Union)
        node2 = direct() & computed("x")
        assert isinstance(node2, Intersect)
        node3 = direct() - computed("x")
        assert isinstance(node3, Difference)
        assert node3.base == direct()

    def test_composite_requires_children(self):
        with pytest.raises(ValueError):
            union([direct()])
        with pytest.raises(ValueError):
            intersect([direct()])
        with pytest.raises(ValueError):
            difference(direct(), [])
