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


class RelationshipError(ValueError):
    """Base error for relationship-tuple (ReBAC) problems."""


class InvalidSubjectError(RelationshipError):
    """Raised when a relationship tuple carries an unusable subject."""


class InvalidTupleError(RelationshipError):
    """Raised when a relationship tuple is malformed."""


class InvalidSchemaError(RelationshipError):
    """Raised when a relationship schema is structurally invalid."""


class NegativeRecursionError(InvalidSchemaError):
    """Raised at definition time when a difference branch creates a
    negative cycle back to the relation itself.

    Such a definition has no well-defined least fixpoint and is rejected
    instead of being silently truncated to ``false`` during evaluation.
    """


class UndefinedRelationError(RelationshipError):
    """Raised when a tuple or query uses a relation not present in the
    schema for the given object type."""


class TupleNotFoundError(RelationshipError):
    """Raised when removing a relationship tuple that does not exist."""
