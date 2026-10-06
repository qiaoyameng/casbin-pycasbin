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

from abc import ABCMeta, abstractmethod


class TransactionalAdapter(metaclass=ABCMeta):
    """TransactionalAdapter is the interface for adapters that can persist a
    batch of policy and grouping rules atomically.

    The contract is:

    - ``begin_transaction`` starts a unit of work. If the adapter cannot offer
      atomic commit it must raise
      ``casbin.persist.errors.TransactionNotSupportedError`` instead of
      returning a transaction object.
    - every method on the returned transaction stages one change; staged
      changes are not visible to other readers until ``commit`` succeeds.
    - ``commit`` makes all staged changes visible at once. It either fully
      succeeds or leaves the storage exactly as it was before the transaction
      began (raising on failure). Emitting one ``add_policy`` call per rule is
      not a valid implementation.
    - ``rollback`` discards the staged changes.

    ``sec`` is "p" for policy rules and "g" for grouping (role) rules.
    """

    @abstractmethod
    def begin_transaction(self):
        """begins a new transaction.

        Returns an object implementing the transaction protocol below. Raises
        TransactionNotSupportedError if atomic commit is unavailable.
        """
        pass


class Transaction(metaclass=ABCMeta):
    """a unit of staged changes that commit atomically."""

    @abstractmethod
    def add_policies(self, sec, ptype, rules):
        """stages rule additions."""
        pass

    @abstractmethod
    def remove_policies(self, sec, ptype, rules):
        """stages rule removals."""
        pass

    @abstractmethod
    def commit(self):
        """applies every staged change atomically.

        On failure the storage must be unchanged.
        """
        pass

    @abstractmethod
    def rollback(self):
        """discards every staged change."""
        pass
