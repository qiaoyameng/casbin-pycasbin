# Copyright 2021 The Casbin Authors. All Rights Reserved.
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

"""Transactional batch updates for policy and grouping rules.

A batch is staged on a :class:`BatchUpdate`, validated against a private
candidate copy of the whole policy view, persisted as one transaction, and only
then published to subsequent enforce calls. Other requests therefore never
observe an intermediate state where some rules of the batch are applied and
others are not.
"""

from collections import namedtuple
from enum import Enum


class BatchValidationError(ValueError):
    """raised when a staged batch is inconsistent with the current policy."""


class BatchOp(Enum):
    ADD = "add"
    REMOVE = "remove"


BatchOperation = namedtuple("BatchOperation", ["op", "sec", "ptype", "rules"])

BatchCommitResult = namedtuple("BatchCommitResult", ["committed", "notified", "version", "operations"])


class BatchUpdate:
    """stages several p/g rule changes and commits them as one transaction.

    Obtain one through :meth:`ManagementEnforcer.batch_update` and either use it
    as a context manager or call :meth:`commit` explicitly. Nothing is applied
    until commit succeeds.
    """

    def __init__(self, enforcer):
        self._enforcer = enforcer
        self._operations = []

    def add_policy(self, *rule):
        """stages an addition to the default ``p`` policy."""
        return self.add_named_policy("p", rule)

    def add_named_policy(self, ptype, rule):
        """stages an addition to a named policy."""
        self._operations.append(BatchOperation(BatchOp.ADD, "p", ptype, [list(rule)]))
        return self

    def add_policies(self, rules):
        """stages several additions to the default ``p`` policy."""
        return self.add_named_policies("p", rules)

    def add_named_policies(self, ptype, rules):
        """stages several additions to a named policy."""
        self._operations.append(BatchOperation(BatchOp.ADD, "p", ptype, [list(rule) for rule in rules]))
        return self

    def remove_policy(self, *rule):
        """stages a removal from the default ``p`` policy."""
        return self.remove_named_policy("p", rule)

    def remove_named_policy(self, ptype, rule):
        """stages a removal from a named policy."""
        self._operations.append(BatchOperation(BatchOp.REMOVE, "p", ptype, [list(rule)]))
        return self

    def remove_policies(self, rules):
        """stages several removals from the default ``p`` policy."""
        return self.remove_named_policies("p", rules)

    def remove_named_policies(self, ptype, rules):
        """stages several removals from a named policy."""
        self._operations.append(BatchOperation(BatchOp.REMOVE, "p", ptype, [list(rule) for rule in rules]))
        return self

    def add_grouping_policy(self, *rule):
        """stages an addition to the default ``g`` grouping policy."""
        return self.add_named_grouping_policy("g", rule)

    def add_named_grouping_policy(self, ptype, rule):
        """stages an addition to a named grouping policy."""
        self._operations.append(BatchOperation(BatchOp.ADD, "g", ptype, [list(rule)]))
        return self

    def add_grouping_policies(self, rules):
        """stages several additions to the default ``g`` grouping policy."""
        return self.add_named_grouping_policies("g", rules)

    def add_named_grouping_policies(self, ptype, rules):
        """stages several additions to a named grouping policy."""
        self._operations.append(BatchOperation(BatchOp.ADD, "g", ptype, [list(rule) for rule in rules]))
        return self

    def remove_grouping_policy(self, *rule):
        """stages a removal from the default ``g`` grouping policy."""
        return self.remove_named_grouping_policy("g", rule)

    def remove_named_grouping_policy(self, ptype, rule):
        """stages a removal from a named grouping policy."""
        self._operations.append(BatchOperation(BatchOp.REMOVE, "g", ptype, [list(rule)]))
        return self

    def remove_grouping_policies(self, rules):
        """stages several removals from the default ``g`` grouping policy."""
        return self.remove_named_grouping_policies("g", rules)

    def remove_named_grouping_policies(self, ptype, rules):
        """stages several removals from a named grouping policy."""
        self._operations.append(BatchOperation(BatchOp.REMOVE, "g", ptype, [list(rule) for rule in rules]))
        return self

    def operations(self):
        """returns the staged operations in staging order."""
        return tuple(self._operations)

    def commit(self):
        """validates, persists and publishes the batch in one step."""
        return self._enforcer._commit_batch(self._operations)

    def rollback(self):
        """discards the staged operations."""
        self._operations = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            self.rollback()
            return False

        self.commit()
        return False
