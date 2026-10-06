# Copyright 2026 The casbin Authors. All Rights Reserved.
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

"""Atomic policy transactions.

A batch admin operation may touch several ``p`` and ``g`` rules at once. Writing
those rules one by one exposes intermediate policy states to concurrent
``enforce`` calls, and some of those intermediate states can temporarily grant
more permission than either the old or the new policy. To avoid that, adapters
that back a batch commit must guarantee that the whole set of changes becomes
durable atomically.

Calling :meth:`Adapter.add_policy` / :meth:`BatchAdapter.add_policies` in a loop
is *not* an atomic commit: an exception halfway through leaves the storage
partially mutated. Adapters that cannot offer a real transaction must not
silently pretend otherwise; they should leave :meth:`begin_transaction`
unimplemented so the enforcer refuses the batch with
:class:`TransactionNotSupportedError`.
"""

__all__ = [
    "TransactionError",
    "TransactionNotSupportedError",
    "RollbackError",
    "Transaction",
    "TransactionalAdapter",
    "begin_transaction",
]


class TransactionError(RuntimeError):
    """Base class for policy transaction errors."""


class TransactionNotSupportedError(TransactionError):
    """Raised when an adapter cannot commit a batch atomically.

    This is different from :class:`RollbackError`: the adapter never promised
    transactional behaviour, so the enforcer rejects the batch up front instead
    of simulating it with sequential single-rule writes.
    """


class RollbackError(TransactionError):
    """Raised when commit failed and the storage could not roll back either.

    Storage may be left in an unknown state, so the in-memory policy is not
    published.
    """


class Transaction:
    """A unit of work that buffers policy changes and commits them atomically.

    Every method records a change inside the transaction; nothing is visible to
    other storage readers until :meth:`commit` succeeds. A transaction may be
    used once: committing or rolling it back invalidates it.
    """

    def add_policy(self, sec, ptype, rule):
        """record adding one rule inside the transaction."""
        raise NotImplementedError

    def remove_policy(self, sec, ptype, rule):
        """record removing one rule inside the transaction."""
        raise NotImplementedError

    def commit(self):
        """make all recorded changes durable and visible atomically.

        Must raise an exception if the changes cannot all be committed, and
        leave the storage as it was before the transaction (or raise
        :class:`RollbackError` if that rollback itself fails).
        """
        raise NotImplementedError

    def rollback(self):
        """discard every recorded change without touching visible storage."""
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        return False


class TransactionalAdapter:
    """Mixin/interface for adapters that support atomic batch commits.

    A plain :class:`~casbin.persist.adapters.BatchAdapter` only groups calls; it
    does not promise atomicity. An adapter opts into atomic batch commits by
    implementing :meth:`begin_transaction` and returning a :class:`Transaction`.
    """

    def begin_transaction(self):
        """return a fresh :class:`Transaction` for one atomic batch commit."""
        raise TransactionNotSupportedError(
            "adapter does not support atomic transactions; refusing a batch commit "
            "that would be simulated with non-atomic per-rule writes"
        )


def begin_transaction(adapter):
    """Return a transaction for *adapter*, or raise a clear error.

    Adapters must explicitly opt in via :meth:`TransactionalAdapter
    .begin_transaction`; merely inheriting ``BatchAdapter`` (so that
    ``add_policies`` exists) is not accepted as an atomicity guarantee.
    """
    begin = getattr(adapter, "begin_transaction", None)
    if not callable(begin):
        raise TransactionNotSupportedError(
            "adapter {!r} provides no begin_transaction(); it cannot guarantee that a "
            "multi-rule batch commits atomically".format(type(adapter).__name__)
        )
    tx = begin()
    if not isinstance(tx, Transaction) and not all(
        callable(getattr(tx, name, None)) for name in ("add_policy", "remove_policy", "commit", "rollback")
    ):
        raise TransactionNotSupportedError(
            "adapter {!r} returned an object without the Transaction contract".format(type(adapter).__name__)
        )
    return tx
