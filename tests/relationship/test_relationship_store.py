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
    RelationshipStore,
    RelationshipTuple,
    User,
    direct,
    computed,
    tuple_userset,
    union,
    intersect,
    difference,
    InvalidTupleError,
    NegativeRecursionError,
    UndefinedRelationError,
)


def make_file_schema():
    """folder.viewer includes direct members and parent folders.
    document.viewer includes direct shares and parent folder viewers,
    minus document.blocked and parent folder .blocked lists."""
    return Schema(
        {
            "folder": {
                "parent": direct(),
                "blocked": direct(),
                "viewer": union([direct(), tuple_userset("parent", "viewer")]),
            },
            "document": {
                "parent": direct(),
                "blocked": direct(),
                "viewer": union([direct(), tuple_userset("parent", "viewer")])
                .subtract(computed("blocked"))
                .subtract(tuple_userset("parent", "blocked")),
            },
            "team": {
                "member": union([direct(), tuple_userset("member", "member")]),
            },
        }
    )


class TestDirectAndUserset:
    def setup_method(self):
        self.store = RelationshipStore(make_file_schema())

    def test_direct_member(self):
        self.store.add_tuple("document", "1", "viewer", "alice")
        assert self.store.check("alice", "document", "1", "viewer")
        assert not self.store.check("bob", "document", "1", "viewer")

    def test_tuple_string_entry(self):
        self.store.add_tuple("document:1#viewer@alice")
        assert self.store.check("alice", "document", "1", "viewer")

    def test_relationship_tuple_object_entry(self):
        self.store.add_tuple(RelationshipTuple("document", "1", "viewer", User("alice")))
        assert self.store.check(User("alice"), "document", "1", "viewer")

    def test_userset_reference_is_followed(self):
        self.store.add_tuple("document", "1", "viewer", "team:eng#member")
        self.store.add_tuple("team", "eng", "member", "carol")
        assert self.store.check("carol", "document", "1", "viewer")

    def test_object_subject_expands_through_member(self):
        # Sharing with a bare object means its member userset.
        self.store.add_tuple("document", "1", "viewer", "team:eng")
        self.store.add_tuple("team", "eng", "member", "carol")
        assert self.store.check("carol", "document", "1", "viewer")

    def test_userset_lists_all_users(self):
        self.store.add_tuple("document", "1", "viewer", "alice")
        self.store.add_tuple("document", "1", "viewer", "bob")
        assert self.store.userset("document", "1", "viewer") == {User("alice"), User("bob")}

    def test_undefined_relation_tuple_rejected(self):
        with pytest.raises(UndefinedRelationError):
            self.store.add_tuple("document", "1", "owner", "alice")

    def test_undefined_relation_query_rejected(self):
        with pytest.raises(UndefinedRelationError):
            self.store.check("alice", "document", "1", "owner")

    def test_remove_tuple(self):
        self.store.add_tuple("document", "1", "viewer", "alice")
        self.store.remove_tuple("document", "1", "viewer", "alice")
        assert not self.store.check("alice", "document", "1", "viewer")

    def test_remove_missing_tuple(self):
        with pytest.raises(InvalidTupleError):
            self.store.remove_tuple("document", "1", "viewer", "nobody")


class TestParentInheritance:
    def setup_method(self):
        self.store = RelationshipStore(make_file_schema())

    def test_inherits_parent_viewer(self):
        self.store.add_tuple("document", "1", "parent", "folder:home")
        self.store.add_tuple("folder", "home", "viewer", "alice")
        assert self.store.check("alice", "document", "1", "viewer")

    def test_direct_share_plus_parent(self):
        self.store.add_tuple("document", "1", "parent", "folder:home")
        self.store.add_tuple("folder", "home", "viewer", "alice")
        self.store.add_tuple("document", "1", "viewer", "bob")
        assert self.store.userset("document", "1", "viewer") == {User("alice"), User("bob")}


class TestDiamondInheritance:
    def setup_method(self):
        # document -> fA, fB ; fA -> fRoot ; fB -> fRoot
        self.store = RelationshipStore(make_file_schema())
        self.store.add_tuple("document", "d", "parent", "folder:fA")
        self.store.add_tuple("document", "d", "parent", "folder:fB")
        self.store.add_tuple("folder", "fA", "parent", "folder:fRoot")
        self.store.add_tuple("folder", "fB", "parent", "folder:fRoot")
        self.store.add_tuple("folder", "fRoot", "viewer", "alice")

    def test_user_reaches_through_all_paths(self):
        assert self.store.check("alice", "document", "d", "viewer")

    def test_userset_is_a_set_no_duplicates(self):
        assert self.store.userset("document", "d", "viewer") == {User("alice")}

    def test_branch_without_user_does_not_grant(self):
        assert not self.store.check("stranger", "document", "d", "viewer")


class TestCyclicTeams:
    def setup_method(self):
        self.store = RelationshipStore(make_file_schema())

    def test_mutually_recursive_teams(self):
        self.store.add_tuple("team", "tA", "member", "team:tB")
        self.store.add_tuple("team", "tB", "member", "team:tA")
        self.store.add_tuple("team", "tA", "member", "bob")
        assert self.store.check("bob", "team", "tA", "member")
        assert self.store.check("bob", "team", "tB", "member")

    def test_self_referential_empty_team(self):
        self.store.add_tuple("team", "tC", "member", "team:tC")
        assert self.store.userset("team", "tC", "member") == set()

    def test_cyclic_team_reached_from_document(self):
        self.store.add_tuple("team", "tA", "member", "team:tB")
        self.store.add_tuple("team", "tB", "member", "team:tA")
        self.store.add_tuple("team", "tA", "member", "bob")
        self.store.add_tuple("folder", "f", "viewer", "team:tA#member")
        self.store.add_tuple("document", "d", "parent", "folder:f")
        assert self.store.check("bob", "document", "d", "viewer")


class TestBlockedOverride:
    def setup_method(self):
        self.store = RelationshipStore(make_file_schema())
        self.store.add_tuple("document", "d", "parent", "folder:fA")
        self.store.add_tuple("document", "d", "parent", "folder:fB")
        self.store.add_tuple("folder", "fA", "viewer", "team:t1#member")
        self.store.add_tuple("folder", "fB", "viewer", "alice")
        self.store.add_tuple("team", "t1", "member", "alice")
        # alice arrives via TWO paths (direct on fB and via team on fA).

    def test_multiple_paths_grant_before_block(self):
        assert self.store.check("alice", "document", "d", "viewer")

    def test_document_block_overrides_all_inherited_paths(self):
        self.store.add_tuple("document", "d", "blocked", "alice")
        assert not self.store.check("alice", "document", "d", "viewer")

    def test_block_on_one_parent_overrides_every_path(self):
        # Difference is applied to the union of every parent's viewers, so a
        # block on any direct parent removes the user regardless of which
        # other inheritance path granted access.
        self.store.add_tuple("folder", "fB", "blocked", "alice")
        assert not self.store.check("alice", "document", "d", "viewer")

    def test_unrelated_parent_block_does_not_grant_or_deny(self):
        # Blocking alice on a folder that is not a parent has no effect.
        self.store.add_tuple("folder", "other", "blocked", "alice")
        assert self.store.check("alice", "document", "d", "viewer")

    def test_block_does_not_affect_other_users(self):
        self.store.add_tuple("folder", "fA", "viewer", "bob")
        self.store.add_tuple("document", "d", "blocked", "alice")
        assert self.store.check("bob", "document", "d", "viewer")
        assert not self.store.check("alice", "document", "d", "viewer")


class TestIntersection:
    def test_intersection_of_relations(self):
        schema = Schema(
            {
                "doc": {
                    "a": direct(),
                    "b": direct(),
                    "both": intersect([computed("a"), computed("b")]),
                }
            }
        )
        store = RelationshipStore(schema)
        store.add_tuple("doc", "1", "a", "alice")
        store.add_tuple("doc", "1", "a", "bob")
        store.add_tuple("doc", "1", "b", "alice")
        store.add_tuple("doc", "1", "b", "carol")
        assert store.userset("doc", "1", "both") == {User("alice")}


class TestFixpointSemantics:
    def test_deep_positive_chain_converges(self):
        schema = Schema(
            {"n": {"next": direct(), "reach": union([direct(), tuple_userset("next", "reach")])}}
        )
        store = RelationshipStore(schema)
        previous = None
        for i in range(600):
            name = "n%d" % i
            if previous is not None:
                store.add_tuple("n", previous, "next", "n:" + name)
            previous = name
        store.add_tuple("n", previous, "reach", "zoe")
        assert store.check("zoe", "n", "n0", "reach")

    def test_finite_data_fixpoint_is_least(self):
        # viewer = direct | viewer must not invent users absent from data.
        schema = Schema({"o": {"viewer": union([direct(), computed("viewer")])}})
        store = RelationshipStore(schema)
        store.add_tuple("o", "1", "viewer", "alice")
        assert store.userset("o", "1", "viewer") == {User("alice")}

    def test_difference_against_fixed_lower_stratum(self):
        # x = viewer \\ blocked with blocked independent of the recursion.
        schema = Schema(
            {
                "o": {
                    "blocked": direct(),
                    "viewer": union([direct(), computed("viewer")]).subtract(computed("blocked")),
                }
            }
        )
        store = RelationshipStore(schema)
        store.add_tuple("o", "1", "viewer", "alice")
        store.add_tuple("o", "1", "viewer", "bob")
        store.add_tuple("o", "1", "blocked", "alice")
        assert store.userset("o", "1", "viewer") == {User("bob")}


class TestDataLevelNegativeCycle:
    def test_tuples_closing_negative_cycle_raise_not_false(self):
        schema = Schema(
            {
                "folder": {
                    "parent": direct(),
                    "flag": difference(direct(), [tuple_userset("parent", "flag")]),
                }
            }
        )
        store = RelationshipStore(schema)
        store.add_tuple("folder", "a", "parent", "folder:b")
        store.add_tuple("folder", "b", "parent", "folder:a")
        with pytest.raises(NegativeRecursionError):
            store.check("u", "folder", "a", "flag")
