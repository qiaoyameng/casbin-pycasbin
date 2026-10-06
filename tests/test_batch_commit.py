# Copyright 2024 The Casbin Authors. All Rights Reserved.
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

import pytest

import casbin
from casbin.core_enforcer import CoreEnforcer
from casbin.batch import BatchCommitResult, BatchValidationError
from casbin.persist import (
    Adapter,
    TransactionalAdapter,
    TransactionCommitError,
    TransactionNotSupportedError,
    PolicyNotificationError,
)


GATED_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = !some(where (p_eft == deny))

[matchers]
m = gate(r.sub, r.obj, r.act) && g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""


class Gate:
    """A matcher helper that pauses registered worker enforces before rule two.

    Lifecycle with two workers:
        gate = Gate()
        workers = [Thread(...), ...]
        for w in workers: w.start()
        gate.arm(*workers)          # or arm() then register
        gate.wait_parked(count=2)   # both are parked after rule one
        ... commit ...
        gate.release()

    Only registered worker threads park; enforce calls made by other threads
    pass straight through, so the test can verify the freshly published view
    without disturbing the parked iterations.
    """

    def __init__(self):
        self._cond = threading.Condition()
        self._registered = set()
        self._armed_idents = set()
        self._parked_count = 0
        self._release = threading.Event()
        self.calls = []
        self._worker_call_counts = {}
        self._count_lock = threading.Lock()

    def reset(self):
        with self._cond:
            self._registered = set()
            self._armed_idents = set()
            self._parked_count = 0
            self._release = threading.Event()
        with self._count_lock:
            self.calls = []
            self._worker_call_counts = {}

    def register(self):
        """called by a worker; blocks until that thread is armed."""
        ident = threading.get_ident()
        with self._cond:
            self._registered.add(ident)
            self._cond.notify_all()
            while ident not in self._armed_idents:
                self._cond.wait()

    def arm(self, *workers):
        """arms registered worker threads (or the given Thread objects)."""
        idents = set()
        for worker in workers:
            idents.add(worker.ident if hasattr(worker, "ident") else worker)
        with self._cond:
            self._release = threading.Event()
            if not idents:
                idents = set(self._registered)
            self._armed_idents.update(idents)
            self._cond.notify_all()

    def wait_parked(self, count=1, timeout=2):
        """waits until ``count`` armed workers are parked between rules."""
        with self._cond:
            return self._cond.wait_for(lambda: self._parked_count >= count, timeout)

    def release(self):
        """lets every parked enforce resume."""
        with self._cond:
            self._armed_idents = set()
        self._release.set()

    def __call__(self, sub, obj, act):
        ident = threading.get_ident()
        with self._cond:
            registered = ident in self._registered

        if not registered:
            # unregistered callers (e.g. the test thread) do not participate
            return True

        with self._count_lock:
            per_worker_call = self._worker_call_counts
            seen = ident in per_worker_call
            count = per_worker_call.get(ident, 0)
            per_worker_call[ident] = count + 1
            self.calls.append((sub, obj, act))

        if not seen:
            with self._cond:
                armed = ident in self._armed_idents
                if armed:
                    self._parked_count += 1
                    self._cond.notify_all()
            if armed:
                self._release.wait(5)
        return True


class InMemoryTransaction:
    def __init__(self, storage, adapter):
        self._storage = storage
        self._adapter = adapter
        self._staged = {"add": [], "remove": []}
        self._closed = False

    def add_policies(self, sec, ptype, rules):
        for rule in rules:
            self._adapter.fail("stage_add")
            self._staged["add"].append((sec, ptype, tuple(rule)))

    def remove_policies(self, sec, ptype, rules):
        for rule in rules:
            self._adapter.fail("stage_remove")
            self._staged["remove"].append((sec, ptype, tuple(rule)))

    def commit(self):
        self._adapter.fail("before_commit")
        new_rules = [list(rule) for rule in self._storage["rules"]]

        def stored_key(stored_rule):
            return stored_rule[0], tuple(stored_rule[1:])

        for _sec, ptype, rule in self._staged["remove"]:
            key = (ptype, tuple(rule))
            if key not in [stored_key(rule) for rule in new_rules]:
                raise RuntimeError("rule to remove is missing in storage: {}".format(rule))
            new_rules = [rule for rule in new_rules if stored_key(rule) != key]
        for _sec, ptype, rule in self._staged["add"]:
            new_rules.append([ptype, *rule])

        # The storage swap itself succeeded before this hook runs: callers
        # treat a failure here as "committed, but something went wrong after".
        self._storage["rules"] = new_rules
        self._storage["version"] += 1
        self._adapter.fail("after_commit")
        self._closed = True

    def rollback(self):
        self._staged = {"add": [], "remove": []}
        self._closed = True


class InMemoryTransactionalAdapter(TransactionalAdapter, Adapter):
    """An in-memory adapter that genuinely commits all staged changes at once.

    ``injected_failures`` maps a phase name to the exception to raise there;
    phases are ``begin``, ``stage_add``, ``stage_remove``, ``before_commit``
    and ``after_commit``. The ``before_commit`` failure happens before storage
    is touched, the ``after_commit`` failure happens after storage is replaced.
    """

    def __init__(self, initial_lines=()):
        self._storage = {"rules": [], "version": 0}
        self.injected_failures = {}
        self.transaction_count = 0
        for line in initial_lines:
            tokens = [token.strip() for token in line.split(",")]
            if tokens and not tokens[0].startswith("#"):
                self._storage["rules"].append(tokens)

    @property
    def version(self):
        return self._storage["version"]

    def stored_rules(self):
        return [(tokens[0], list(tokens[1:])) for tokens in self._storage["rules"]]

    def fail(self, phase):
        error = self.injected_failures.pop(phase, None)
        if error is not None:
            raise error

    def load_policy(self, model):
        for tokens in self._storage["rules"]:
            ptype = tokens[0]
            sec = ptype[0]
            model.model[sec][ptype].policy.append(tokens[1:])

    def begin_transaction(self):
        self.fail("begin")
        self.transaction_count += 1
        return InMemoryTransaction(self._storage, self)


class NonTransactionalAdapter(Adapter):
    """An adapter with single-rule writes but no atomic commit capability."""

    def __init__(self):
        self.written = []

    def load_policy(self, model):
        for sec, ptype, rule in self.written:
            model.model[sec][ptype].policy.append(rule)

    def add_policy(self, sec, ptype, rule):
        self.written.append((sec, ptype, list(rule)))

    def remove_policy(self, sec, ptype, rule):
        self.written = [
            item
            for item in self.written
            if not (item[0] == sec and item[1] == ptype and item[2] == rule)
        ]


class ExplodingWatcher:
    def __init__(self):
        self.notifications = 0

    def update(self):
        self.notifications += 1
        raise RuntimeError("watcher backend is down")

    def update_for_batch_update(self, operations):
        self.notifications += 1
        raise RuntimeError("watcher backend is down")


class CountingWatcher:
    def __init__(self):
        self.notifications = 0
        self.operations = None

    def update_for_batch_update(self, operations):
        self.notifications += 1
        self.operations = list(operations)


def make_gated_enforcer(adapter, gate):
    model = CoreEnforcer.new_model(text=GATED_MODEL)
    enforcer = casbin.Enforcer(model, adapter)
    enforcer.add_function("gate", gate)
    return enforcer


def initial_lines():
    return [
        "p, admin, data, read, allow",
        "p, admin, data, write, deny",
        "g, alice, admin",
    ]


class TestBatchCommit:
    def test_batch_commits_all_p_and_g_rules_together(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        enforcer = make_gated_enforcer(adapter, Gate())

        result = (
            enforcer.batch_update()
            .add_policies([["alice", "data", "read", "allow"]])
            .remove_grouping_policy("alice", "admin")
            .add_grouping_policy("bob", "admin")
            .commit()
        )

        assert isinstance(result, BatchCommitResult)
        assert result.committed is True
        assert result.version == 2
        assert enforcer.get_policy_version() == 2
        assert adapter.transaction_count == 1
        assert enforcer.enforce("bob", "data", "read") is True
        # bob inherits the write-deny rule
        assert enforcer.enforce("bob", "data", "write") is False
        # alice lost the admin role but kept the direct read allow
        assert enforcer.enforce("alice", "data", "read") is True
        # without the role nothing denies writes either: deny-override default is allow
        assert enforcer.enforce("alice", "data", "write") is True

    def test_batch_update_as_context_manager(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        enforcer = make_gated_enforcer(adapter, Gate())

        with enforcer.batch_update() as batch:
            batch.add_policy("carol", "data", "read", "allow")

        assert enforcer.enforce("carol", "data", "read") is True
        assert adapter.version == 1

    def test_non_transactional_adapter_is_rejected(self):
        adapter = NonTransactionalAdapter()
        enforcer = casbin.Enforcer(CoreEnforcer.new_model(text=GATED_MODEL), adapter)
        enforcer.add_function("gate", lambda *args: True)

        with pytest.raises(TransactionNotSupportedError):
            enforcer.batch_update().add_policy("alice", "data", "read", "allow").commit()

        # nothing was written and the live view is untouched
        assert adapter.written == []
        assert enforcer.get_policy_version() == 1

    def test_validation_failure_persists_nothing_and_publishes_nothing(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        enforcer = make_gated_enforcer(adapter, Gate())
        before = enforcer.get_policy()

        with pytest.raises(BatchValidationError):
            enforcer.batch_update().remove_policy("alice", "data", "read", "allow").commit()

        assert adapter.transaction_count == 0
        assert adapter.version == 0
        assert enforcer.get_policy() == before
        assert enforcer.get_policy_version() == 1

    def test_failure_before_commit_rolls_back_and_keeps_old_view(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        enforcer = make_gated_enforcer(adapter, Gate())

        adapter.injected_failures["before_commit"] = RuntimeError("disk on fire")

        with pytest.raises(TransactionCommitError):
            enforcer.batch_update().add_policy("dave", "data", "read", "allow").commit()

        # storage untouched, old version still visible
        assert adapter.version == 0
        assert enforcer.get_policy_version() == 1
        assert enforcer.enforce("alice", "data", "read") is True
        assert ["dave", "data", "read", "allow"] not in enforcer.get_policy()
        assert enforcer.get_grouping_policy() == [["alice", "admin"]]

    def test_failure_during_staging_rolls_back(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        enforcer = make_gated_enforcer(adapter, Gate())

        adapter.injected_failures["stage_add"] = RuntimeError("stage boom")

        with pytest.raises(TransactionCommitError):
            enforcer.batch_update().add_policy("dave", "data", "read", "allow").commit()

        assert adapter.version == 0
        assert enforcer.get_policy_version() == 1
        assert ["dave", "data", "read", "allow"] not in enforcer.get_policy()

    def test_failure_after_commit_is_distinguished_as_committed(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        enforcer = make_gated_enforcer(adapter, Gate())

        adapter.injected_failures["after_commit"] = RuntimeError("commit journal lost")

        with pytest.raises(TransactionCommitError):
            enforcer.batch_update().add_policy("dave", "data", "read", "allow").commit()

        # The failure happened after the storage swap: storage has the change.
        assert adapter.version == 1

    def test_notification_failure_reports_committed_state(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        gate = Gate()
        enforcer = make_gated_enforcer(adapter, gate)
        watcher = ExplodingWatcher()
        enforcer.set_watcher(watcher)

        with pytest.raises(PolicyNotificationError) as exc_info:
            enforcer.batch_update().add_policy("dave", "data", "read", "allow").commit()

        assert exc_info.value.committed is True
        # The policy really did commit: later requests see the new version.
        assert enforcer.get_policy_version() == 2
        assert enforcer.enforce("dave", "data", "read") is True
        # exactly one notification attempt for the one batch
        assert watcher.notifications == 1

    def test_watcher_is_notified_exactly_once_per_commit(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        enforcer = make_gated_enforcer(adapter, Gate())
        watcher = CountingWatcher()
        enforcer.set_watcher(watcher)

        enforcer.batch_update().add_policy("dave", "data", "read", "allow").remove_policy(
            "admin", "data", "write", "deny"
        ).commit()

        assert watcher.notifications == 1
        assert len(watcher.operations) == 2

    def test_inflight_enforce_sees_one_consistent_view(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        gate = Gate()
        enforcer = make_gated_enforcer(adapter, gate)

        result_holder = {}

        def old_view_request():
            gate.register()
            result_holder["result"] = enforcer.enforce("alice", "data", "write")
            result_holder["calls"] = list(gate.calls)

        worker = threading.Thread(target=old_view_request)
        worker.start()
        gate.arm()

        # Wait until the matcher has evaluated exactly one rule of the old view.
        assert gate.wait_parked()
        assert len(gate.calls) == 1

        committed = threading.Event()

        def switch_version():
            (
                enforcer.batch_update()
                .remove_grouping_policy("alice", "admin")
                .add_grouping_policy("bob", "admin")
                .commit()
            )
            committed.set()

        switcher = threading.Thread(target=switch_version)
        switcher.start()
        assert committed.wait(2)
        switcher.join()

        # The switch is published: new requests see the new view. bob is admin
        # now, alice is not.
        assert enforcer.enforce("bob", "data", "read") is True
        assert enforcer.enforce("bob", "data", "write") is False
        # alice has no role and no direct rule left, so nothing denies her:
        # deny-override on an empty match set is allow.
        assert enforcer.enforce("alice", "data", "write") is True

        gate.release()
        worker.join(2)
        assert not worker.is_alive()

        # The parked enforce entered with the old view where alice was admin and
        # the write rule denied her: its result is False, whereas the new view
        # would give True. A mixed view would also give True (no deny matched),
        # so False proves it kept evaluating the old rules.
        assert result_holder["result"] is False
        # Iteration resumed and evaluated the second rule of the same snapshot.
        assert len(result_holder["calls"]) == 2

    def test_two_inflight_enforces_share_no_mixed_view(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        gate = Gate()
        enforcer = make_gated_enforcer(adapter, gate)

        results = {}

        def request(name):
            gate.register()
            results[name] = enforcer.enforce("alice", "data", "write")

        workers = [threading.Thread(target=request, args=(name,)) for name in ("a", "b")]
        for worker in workers:
            worker.start()
        gate.arm()

        # Both workers are parked after their first rule.
        assert gate.wait_parked(count=2)

        # Both parked between rules; publish the switch while they wait.
        (
            enforcer.batch_update()
            .remove_grouping_policy("alice", "admin")
            .add_grouping_policy("bob", "admin")
            .commit()
        )

        gate.release()
        for worker in workers:
            worker.join(2)
            assert not worker.is_alive()

        # Both entered with the old view: the write-deny rule matched and the
        # result is False. A mixed view (new g, old p) would have produced True.
        assert results == {"a": False, "b": False}

    def test_batch_without_adapter_publishes_in_memory_only(self):
        # no adapter: the batch still validates and publishes atomically in
        # memory, and no transaction support is required
        enforcer = casbin.Enforcer(CoreEnforcer.new_model(text=GATED_MODEL))
        enforcer.add_function("gate", lambda *args: True)

        result = (
            enforcer.batch_update()
            .add_policies([["alice", "data", "read", "allow"]])
            .add_grouping_policy("alice", "admin")
            .commit()
        )

        assert result.committed is True
        assert enforcer.enforce("alice", "data", "read") is True
        assert enforcer.enforce("alice", "data", "write") is True

    def test_synced_enforcer_batch_commits_under_write_lock(self):
        adapter = InMemoryTransactionalAdapter(initial_lines())
        enforcer = casbin.SyncedEnforcer(CoreEnforcer.new_model(text=GATED_MODEL), adapter)
        enforcer.add_function("gate", lambda *args: True)

        result = (
            enforcer.batch_update()
            .add_policies([["carol", "data", "read", "allow"]])
            .add_grouping_policy("carol", "admin")
            .commit()
        )

        assert result.committed is True
        assert enforcer.enforce("carol", "data", "read") is True
        # the inherited write deny still applies
        assert enforcer.enforce("carol", "data", "write") is False
