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

from casbin.relationship import (
    Schema,
    RelationshipEnforcer,
    RelationshipStore,
    direct,
    computed,
    tuple_userset,
    union,
)


def schema():
    return Schema(
        {
            "folder": {
                "viewer": union([direct(), tuple_userset("parent", "viewer")]),
                "parent": direct(),
            },
            "document": {
                "parent": direct(),
                "blocked": direct(),
                "viewer": union([direct(), tuple_userset("parent", "viewer")]).subtract(
                    computed("blocked")
                ),
            },
            "team": {"member": union([direct(), tuple_userset("member", "member")])},
        }
    )


def populate(store):
    store.add_tuple("folder", "f", "viewer", "alice")
    store.add_tuple("folder", "f", "viewer", "team:eng#member")
    store.add_tuple("team", "eng", "member", "team:eng-leads")
    store.add_tuple("team", "eng-leads", "member", "carol")
    store.add_tuple("document", "d", "parent", "folder:f")
    store.add_tuple("document", "d", "viewer", "bob")


class TestRelationshipEnforcer:
    def test_enforce_allows_inherited_and_direct(self):
        enforcer = RelationshipEnforcer(schema())
        populate(enforcer)
        assert enforcer.enforce("alice", "document", "d", "viewer")
        assert enforcer.enforce("bob", "document", "d", "viewer")
        assert enforcer.enforce("carol", "document", "d", "viewer")

    def test_enforce_denies_unknown_user(self):
        enforcer = RelationshipEnforcer(schema())
        populate(enforcer)
        assert not enforcer.enforce("nobody", "document", "d", "viewer")

    def test_enforce_combined_object_string(self):
        enforcer = RelationshipEnforcer(schema())
        populate(enforcer)
        assert enforcer.enforce("alice", "document:d#viewer")
        assert not enforcer.enforce("nobody", "document:d#viewer")

    def test_enforce_block_override(self):
        enforcer = RelationshipEnforcer(schema())
        populate(enforcer)
        enforcer.add_tuple("document", "d", "blocked", "alice")
        assert not enforcer.enforce("alice", "document", "d", "viewer")
        assert enforcer.enforce("bob", "document", "d", "viewer")

    def test_uses_provided_store(self):
        store = RelationshipStore(schema())
        populate(store)
        enforcer = RelationshipEnforcer(store=store)
        assert enforcer.enforce("carol", "document", "d", "viewer")

    def test_underlying_casbin_enforcer_is_present(self):
        enforcer = RelationshipEnforcer(schema())
        # The matcher is executed through the normal Casbin machinery.
        assert hasattr(enforcer.enforcer, "enforce")
        assert callable(enforcer.enforcer.fm.get_functions()["checkRelation"])

    def test_no_external_state(self):
        # Two independent stores/enforcers do not share tuples.
        e1 = RelationshipEnforcer(schema())
        e2 = RelationshipEnforcer(schema())
        e1.add_tuple("document", "d", "viewer", "alice")
        assert e1.enforce("alice", "document", "d", "viewer")
        assert not e2.enforce("alice", "document", "d", "viewer")
