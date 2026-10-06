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

"""Relationship-based access control (ReBAC) with relationship tuples.

Run with the project environment::

    python examples/relationship_example.py
"""

from casbin.relationship import (
    RelationshipEnforcer,
    Schema,
    computed,
    direct,
    tuple_userset,
    union,
)

# A schema describes, for every object type, how each relation is derived.
schema = Schema(
    {
        "folder": {
            "parent": direct(),
            "blocked": direct(),
            # folder viewers = direct members, or viewers of a parent folder
            "viewer": union([direct(), tuple_userset("parent", "viewer")]),
        },
        "document": {
            "parent": direct(),
            "blocked": direct(),
            # document.viewer = direct shares + parent folder viewers,
            # minus document.blocked minus parent folders' blocked lists
            "viewer": union([direct(), tuple_userset("parent", "viewer")])
            .subtract(computed("blocked"))
            .subtract(tuple_userset("parent", "blocked")),
        },
        "team": {
            # teams may contain other teams, recursively
            "member": union([direct(), tuple_userset("member", "member")]),
        },
    }
)

enforcer = RelationshipEnforcer(schema)

# Relationship tuples: object type:id#relation -> subject.
enforcer.add_tuple("folder:home#viewer@team:eng")
enforcer.add_tuple("team:eng#member@team:eng-leads")
enforcer.add_tuple("team:eng-leads#member@carol")
enforcer.add_tuple("document:design.doc#parent@folder:home")
enforcer.add_tuple("document:design.doc#viewer@bob")

print("carol (via nested team) can view:",
      enforcer.enforce("carol", "document", "design.doc", "viewer"))
print("bob (direct share) can view:",
      enforcer.enforce("bob", "document", "design.doc", "viewer"))
print("stranger can view:",
      enforcer.enforce("stranger", "document", "design.doc", "viewer"))

# A block overrides every inherited path.
enforcer.add_tuple("document:design.doc#blocked@carol")
print("carol after block can view:",
      enforcer.enforce("carol", "document", "design.doc", "viewer"))
print("bob still can view:",
      enforcer.enforce("bob", "document", "design.doc", "viewer"))
