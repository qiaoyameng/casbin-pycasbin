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

"""Batch policy commits with atomic publish.

A :class:`PolicyBatch` collects several ``p`` and ``g`` rule changes without
touching the live policy. On :meth:`commit` the changes are applied to a
*candidate* copy of the whole model (role links included), validated there,
persisted through an adapter transaction, and only then published by swapping
the enforcer's snapshot. An ``enforce`` call that started before the swap keeps
using the complete old view for its whole duration; later calls see the complete
new view. No request ever observes a half-applied mix.
"""

import copy
from casbin.persist.transaction import (
    RollbackError,
    TransactionError,
    begin_transaction,
)

POLICY_ADD = "add"
POLICY_REMOVE = "remove"


class BatchValidationError(ValueError):
    """a staged batch cannot be applied to the current policy."""


class CommitResult:
    """Outcome of a batch commit.

    ``committed`` is True only after the adapter transaction committed *and* the
    new view was published. ``notified`` reports the watcher notification; when
    the commit succeeded but notification failed, ``committed`` stays True and
    ``notify_error`` carries the failure, so callers can distinguish
    "committed but notify failed" from "commit failed".
    """

    __slots__ = ("committed", "notified", "notify_error")

    def __init__(self, committed, notified, notify_error=None):
        self.committed = committed
        self.notified = notified
        self.notify_error = notify_error

    def __repr__(self):
        return "CommitResult(committed={!r}, notified={!r}, notify_error={!r})".format(
            self.committed, self.notified, self.notify_error
        )


class PolicyBatch:
    """Stages p/g rule changes and publishes them in one atomic commit."""

    def __init__(self, enforcer):
        self._e = enforcer
        self._changes = []
        self._closed = False

    def _stage(self, op, sec, ptype, rule):
        if self._closed:
            raise RuntimeError("policy batch has already been committed or rolled back")
        rule = [str(tok) for tok in rule]
        if not rule:
            raise BatchValidationError("empty rule is not allowed")
        self._changes.append((op, sec, ptype, rule))
        return self

    def add(self, sec, ptype, rule):
        """stage adding one rule to section ``sec`` (``"p"`` or ``"g"``)."""
        self._check_section(sec)
        return self._stage(POLICY_ADD, sec, ptype, rule)

    def remove(self, sec, ptype, rule):
        """stage removing one rule from section ``sec``."""
        self._check_section(sec)
        return self._stage(POLICY_REMOVE, sec, ptype, rule)

    def add_policy(self, rule):
        """stage adding one ``p`` (authorization) rule."""
        return self.add("p", "p", rule)

    def remove_policy(self, rule):
        """stage removing one ``p`` rule."""
        return self.remove("p", "p", rule)

    def add_named_policy(self, ptype, rule):
        return self.add("p", ptype, rule)

    def remove_named_policy(self, ptype, rule):
        return self.remove("p", ptype, rule)

    def add_grouping_policy(self, rule):
        """stage adding one ``g`` (role inheritance) rule."""
        return self.add("g", "g", rule)

    def remove_grouping_policy(self, rule):
        """stage removing one ``g`` rule."""
        return self.remove("g", "g", rule)

    def add_named_grouping_policy(self, ptype, rule):
        return self.add("g", ptype, rule)

    def remove_named_grouping_policy(self, ptype, rule):
        return self.remove("g", ptype, rule)

    @staticmethod
    def _check_section(sec):
        if sec not in ("p", "g"):
            raise BatchValidationError("section must be 'p' or 'g', got {!r}".format(sec))

    @property
    def changes(self):
        """the staged ``(op, sec, ptype, rule)`` tuples (rule copies)."""
        return [(op, sec, ptype, rule[:]) for op, sec, ptype, rule in self._changes]

    def rollback(self):
        """discard all staged changes without touching policy or storage."""
        self._closed = True
        self._changes = []
        return CommitResult(False, False)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.rollback()
            return False
        self.commit()
        return False

    def _build_candidate(self):
        """apply staged changes to an isolated model copy and rebuild its view."""
        current = self._e.current_snapshot()
        candidate = copy.deepcopy(current.model)

        for op, sec, ptype, rule in self._changes:
            if sec not in candidate.keys() or ptype not in candidate[sec]:
                raise BatchValidationError("unknown {} type: {!r}".format(sec, ptype))
            ast = candidate[sec][ptype]
            if sec == "p" and len(rule) != len(ast.tokens):
                raise BatchValidationError(
                    "rule {} has {} fields but policy {} expects {}".format(
                        rule, len(rule), ptype, len(ast.tokens)
                    )
                )
            if sec == "g" and len(rule) < ast.value.count("_"):
                raise BatchValidationError("grouping rule {} is too short for {}".format(rule, ast.value))

            if op == POLICY_ADD:
                if candidate.has_policy(sec, ptype, rule):
                    raise BatchValidationError("rule already exists: {} {}".format(ptype, rule))
                if not candidate.add_policy(sec, ptype, rule):
                    raise BatchValidationError("could not add rule: {} {}".format(ptype, rule))
            else:
                if not candidate.has_policy(sec, ptype, rule):
                    raise BatchValidationError("missing rule to remove: {} {}".format(ptype, rule))
                if not candidate.remove_policy(sec, ptype, rule):
                    raise BatchValidationError("could not remove rule: {} {}".format(ptype, rule))

        candidate.sort_policies_by_subject_hierarchy()
        candidate.sort_policies_by_priority()

        rm_map, cond_rm_map = self._e.clone_role_managers(candidate)
        for rm in rm_map.values():
            rm.clear()
        if rm_map:
            candidate.build_role_links(rm_map)
        for crm in cond_rm_map.values():
            crm.clear()
        if cond_rm_map:
            candidate.build_conditional_role_links(cond_rm_map)

        return candidate, rm_map, cond_rm_map

    def commit(self):
        """validate, persist atomically, then publish the new view once."""
        if self._closed:
            raise RuntimeError("policy batch has already been committed or rolled back")
        self._closed = True

        if not self._changes:
            return CommitResult(True, True)

        # Fully validate on an isolated candidate before touching storage.
        candidate, rm_map, cond_rm_map = self._build_candidate()

        e = self._e
        auto_save = e.adapter is not None and e.auto_save

        if auto_save:
            # Raises TransactionNotSupportedError for adapters without a real
            # transaction contract; sequential writes are never substituted.
            tx = begin_transaction(e.adapter)
            try:
                for op, sec, ptype, rule in self._changes:
                    if op == POLICY_ADD:
                        tx.add_policy(sec, ptype, rule)
                    else:
                        tx.remove_policy(sec, ptype, rule)
                tx.commit()
            except TransactionError:
                raise
            except Exception as exc:
                try:
                    tx.rollback()
                except Exception as rb_exc:
                    raise RollbackError("commit failed and rollback failed") from rb_exc
                raise exc

        # Durable commit succeeded (or nothing to persist): publish atomically.
        e.publish_snapshot(candidate, rm_map, cond_rm_map)

        result = self._notify(self.changes)
        self._changes = []
        return result

    def _notify(self, changes):
        """notify the watcher exactly once after a successful publish."""
        e = self._e
        if not (e.watcher and e.auto_notify_watcher):
            return CommitResult(True, True)

        try:
            update_for_commit = getattr(e.watcher, "update_for_commit_policies", None)
            if callable(update_for_commit):
                update_for_commit(changes)
            else:
                e.watcher.update()
        except Exception as exc:
            # Committed and visible; only the notification failed.
            return CommitResult(True, False, exc)

        return CommitResult(True, True)
