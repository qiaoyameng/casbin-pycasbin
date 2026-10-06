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

import threading
from unittest import TestCase

import casbin
from casbin.persist import Adapter, BatchAdapter
from casbin.persist.transaction import (
    Transaction,
    TransactionalAdapter,
    TransactionNotSupportedError,
)

from tests.test_enforcer import get_examples


class MemoryTransaction(Transaction):
    """stages changes in a private copy and publishes on commit (atomic)."""

    def __init__(self, adapter):
        self._adapter = adapter
        self._staged = []
        self._done = False

    def add_policy(self, sec, ptype, rule):
        self._staged.append(("add", sec, ptype, tuple(rule)))

    def remove_policy(self, sec, ptype, rule):
        self._staged.append(("remove", sec, ptype, tuple(rule)))

    def commit(self):
        if self._done:
            raise RuntimeError("transaction already finished")
        self._done = True
        hook = self._adapter.on_commit
        if hook is not None:
            hook(self)
        # Only mutate the visible state once, here at the end.
        with self._adapter.lock:
            for op, sec, ptype, rule in self._staged:
                rules = self._adapter.rules.setdefault((sec, ptype), set())
                if op == "add":
                    rules.add(rule)
                else:
                    rules.discard(rule)
        self._adapter.commits += 1

    def rollback(self):
        self._done = True
        if getattr(self._adapter, "rollback_fails", False) or getattr(MemoryTransaction, "_rollback_fails", False):
            raise RuntimeError("cannot roll back")
        self._staged = []
        self._adapter.rollbacks += 1


class MemoryTransactionalAdapter(Adapter, TransactionalAdapter):
    """in-memory adapter that supports real atomic transactions."""

    def __init__(self):
        self.rules = {}
        self.lock = threading.Lock()
        self.commits = 0
        self.rollbacks = 0
        self.on_commit = None
        self.fail_begin = False
        self.begin_count = 0

    def seed(self, sec, ptype, rules):
        self.rules[(sec, ptype)] = {tuple(r) for r in rules}

    def load_policy(self, model):
        for (sec, ptype), rules in self.rules.items():
            for rule in sorted(rules):
                model.add_policy(sec, ptype, list(rule))

    def begin_transaction(self):
        self.begin_count += 1
        if self.fail_begin:
            raise TransactionNotSupportedError("transactional storage is offline")
        return MemoryTransaction(self)


class NonTransactionalBatchAdapter(BatchAdapter):
    """groups writes but cannot commit a mixed batch atomically."""

    def __init__(self):
        self.ops = []

    def add_policies(self, sec, ptype, rules):
        for rule in rules:
            self.ops.append(("add", sec, ptype, tuple(rule)))

    def remove_policies(self, sec, ptype, rules):
        for rule in rules:
            self.ops.append(("remove", sec, ptype, tuple(rule)))


class RecordingWatcher:
    def __init__(self, fail=False):
        self.updates = 0
        self.commits = []
        self._fail = fail

    def update(self):
        self.updates += 1
        if self._fail:
            raise RuntimeError("notification channel down")

    def update_for_commit_policies(self, changes):
        self.commits.append(list(changes))
        self.updates += 1
        if self._fail:
            raise RuntimeError("notification channel down")


def rbac_adapter():
    adapter = MemoryTransactionalAdapter()
    adapter.seed("p", "p", [
        ["alice", "data1", "read"],
        ["bob", "data2", "write"],
        ["data2_admin", "data2", "read"],
        ["data2_admin", "data2", "write"],
    ])
    adapter.seed("g", "g", [["alice", "data2_admin"]])
    return adapter


class TestPolicyBatchCommit(TestCase):
    def setUp(self):
        self.adapter = rbac_adapter()
        self.e = casbin.Enforcer(get_examples("rbac_model.conf"), self.adapter)

    def test_batch_visible_only_after_commit(self):
        batch = self.e.new_policy_batch()
        batch.add_policy(["bob", "data1", "read"])
        batch.remove_policy(["bob", "data2", "write"])
        batch.add_grouping_policy(["alice", "data1_admin"])
        batch.add_policy(["data1_admin", "data1", "read"])
        batch.remove_grouping_policy(["alice", "data2_admin"])

        # staged but not committed: live view is untouched
        self.assertFalse(self.e.enforce("bob", "data1", "read"))
        self.assertTrue(self.e.enforce("alice", "data2", "read"))
        self.assertFalse(self.e.enforce("alice", "data1", "write"))

        result = batch.commit()
        self.assertTrue(result.committed)
        self.assertTrue(result.notified)
        self.assertIsNone(result.notify_error)

        # bob's own write rule is gone
        self.assertFalse(self.e.enforce("bob", "data2", "write"))
        self.assertTrue(self.e.enforce("bob", "data1", "read"))
        # alice's role switch is atomic: data2 gone, data1 granted through the new link
        self.assertFalse(self.e.enforce("alice", "data2", "read"))
        self.assertTrue(self.e.enforce("alice", "data1", "read"))
        self.assertFalse(self.e.enforce("alice", "data1", "write"))

    def test_commit_persists_all_rules_in_one_transaction(self):
        ops = []

        def capture(tx):
            ops.extend(tx._staged)

        self.adapter.on_commit = capture
        with self.e.policy_batch() as batch:
            batch.add_policy(["carol", "data1", "read"])
            batch.remove_policy(["bob", "data2", "write"])

        self.assertEqual(self.adapter.begin_count, 1)
        self.assertEqual(self.adapter.commits, 1)
        self.assertEqual(
            sorted(ops),
            [
                ("add", "p", "p", ("carol", "data1", "read")),
                ("remove", "p", "p", ("bob", "data2", "write")),
            ],
        )

        # reload through a fresh enforcer to prove durability
        fresh = casbin.Enforcer(get_examples("rbac_model.conf"), self.adapter)
        self.assertTrue(fresh.enforce("carol", "data1", "read"))
        self.assertFalse(fresh.enforce("bob", "data2", "write"))

    def test_validation_failure_changes_nothing(self):
        with self.assertRaises(casbin.BatchValidationError):
            with self.e.policy_batch() as batch:
                batch.add_policy(["alice", "data1", "read"])  # duplicate
                batch.add_policy(["carol", "data1", "read"])

        self.assertEqual(self.adapter.begin_count, 0)
        self.assertEqual(self.adapter.commits, 0)
        self.assertTrue(self.e.enforce("alice", "data1", "read"))
        self.assertFalse(self.e.enforce("carol", "data1", "read"))

    def test_commit_exception_rolls_back_and_keeps_old_view(self):
        def fail(tx):
            raise RuntimeError("storage exploded during commit")

        self.adapter.on_commit = fail
        with self.assertRaisesRegex(RuntimeError, "storage exploded"):
            with self.e.policy_batch() as batch:
                batch.add_policy(["carol", "data1", "read"])

        self.assertEqual(self.adapter.commits, 0)
        self.assertEqual(self.adapter.rollbacks, 1)
        self.assertFalse(self.e.enforce("carol", "data1", "read"))
        self.assertTrue(self.e.enforce("bob", "data2", "write"))

    def test_exception_before_publish_does_not_notify(self):
        watcher = RecordingWatcher()
        self.e.set_watcher(watcher)
        self.adapter.on_commit = lambda tx: (_ for _ in ()).throw(RuntimeError("boom"))
        with self.assertRaises(RuntimeError):
            with self.e.policy_batch() as batch:
                batch.add_policy(["carol", "data1", "read"])
        self.assertEqual(watcher.updates, 0)

    def test_notify_failure_is_distinguishable_from_commit_failure(self):
        watcher = RecordingWatcher(fail=True)
        self.e.set_watcher(watcher)
        result = self.e.new_policy_batch().add_policy(["carol", "data1", "read"]).commit()
        self.assertTrue(result.committed)
        self.assertFalse(result.notified)
        self.assertIsInstance(result.notify_error, RuntimeError)
        # still visible
        self.assertTrue(self.e.enforce("carol", "data1", "read"))

    def test_watcher_notified_exactly_once_per_commit(self):
        watcher = RecordingWatcher()
        self.e.set_watcher(watcher)
        with self.e.policy_batch() as batch:
            batch.add_policy(["carol", "data1", "read"])
            batch.add_policy(["dave", "data1", "read"])
            batch.remove_policy(["bob", "data2", "write"])
        self.assertEqual(watcher.updates, 1)
        self.assertEqual(len(watcher.commits), 1)
        self.assertEqual(len(watcher.commits[0]), 3)

    def test_non_transactional_adapter_is_refused(self):
        e = casbin.Enforcer(get_examples("rbac_model.conf"), NonTransactionalBatchAdapter())
        with self.assertRaises(TransactionNotSupportedError):
            with e.policy_batch() as batch:
                batch.add_policy(["alice", "data1", "read"])

    def test_adapter_that_used_to_transact_now_refuses(self):
        self.adapter.fail_begin = True
        with self.assertRaises(TransactionNotSupportedError):
            with self.e.policy_batch() as batch:
                batch.add_policy(["carol", "data1", "read"])
        self.assertFalse(self.e.enforce("carol", "data1", "read"))

    def test_context_manager_rolls_back_on_exception(self):
        try:
            with self.e.policy_batch() as batch:
                batch.add_policy(["carol", "data1", "read"])
                raise ValueError("client changed its mind")
        except ValueError:
            pass
        self.assertEqual(self.adapter.begin_count, 0)
        self.assertFalse(self.e.enforce("carol", "data1", "read"))

    def test_failed_rollback_surfaces_and_keeps_old_view(self):
        def fail(tx):
            raise RuntimeError("commit failed")

        self.adapter.on_commit = fail
        from casbin.persist.transaction import RollbackError

        MemoryTransaction._rollback_fails = True
        try:
            with self.assertRaises(RollbackError):
                with self.e.policy_batch() as batch:
                    batch.add_policy(["carol", "data1", "read"])
        finally:
            MemoryTransaction._rollback_fails = False

        # nothing published, so the in-memory view is the old policy
        self.assertFalse(self.e.enforce("carol", "data1", "read"))
        self.assertTrue(self.e.enforce("bob", "data2", "write"))


class TestSnapshotConsistency(TestCase):
    """a paused matcher must never read a half-switched policy/role graph."""

    def test_inflight_enforce_uses_entry_view(self):
        adapter = rbac_adapter()
        e = casbin.Enforcer(get_examples("rbac_pause_model.conf"), adapter)

        reached = threading.Event()
        release = threading.Event()

        def pause_hook(r_sub, p_sub):
            # pause while the rule that grants alice (the admin) access is evaluated,
            # i.e. between two rules of the entry snapshot, before the batch commit
            if p_sub == "data2_admin" and not reached.is_set():
                reached.set()
                release.wait(timeout=10)
            return True

        e.add_function("pauseHook", pause_hook)

        result_holder = {}

        def worker():
            result_holder["alice_data2_read"] = e.enforce("alice", "data2", "read")

        thread = threading.Thread(target=worker)
        thread.start()
        self.assertTrue(reached.wait(timeout=5))

        # While enforce is frozen mid-scan: remove the only thing granting alice
        # access to data2 (both the p rule for the role and the g link).
        with e.policy_batch() as batch:
            batch.remove_policy(["data2_admin", "data2", "read"])
            batch.remove_grouping_policy(["alice", "data2_admin"])

        # A request entering after publish already sees the new (denying) view.
        self.assertFalse(e.enforce("alice", "data2", "read"))

        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())

        # the in-flight request kept its entry snapshot and still allowed
        self.assertTrue(result_holder["alice_data2_read"])

    def test_concurrent_commits_publish_distinct_whole_views(self):
        adapter = rbac_adapter()
        e = casbin.Enforcer(get_examples("rbac_model.conf"), adapter)

        versions = []

        def commit(rules):
            with e.policy_batch() as batch:
                for rule in rules:
                    batch.add_policy(rule)
            versions.append(e.current_snapshot().version)

        t1 = threading.Thread(target=commit, args=([["u1", "data1", "read"]],))
        t2 = threading.Thread(target=commit, args=([["u2", "data1", "read"], ["u2", "data2", "write"]],))
        t1.start(); t2.start(); t1.join(); t2.join()

        self.assertTrue(e.enforce("u1", "data1", "read"))
        self.assertTrue(e.enforce("u2", "data2", "write"))
        # every published snapshot is a whole, consistent model
        self.assertGreaterEqual(e.current_snapshot().version, 2)
