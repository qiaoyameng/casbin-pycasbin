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

import os
from datetime import datetime, timedelta, timezone
from unittest import TestCase

import casbin
from casbin.model import Model
from casbin.util.temporal import contains_moment

UTC = timezone.utc
EPSILON = timedelta(microseconds=1)


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


def at(day, hour=0, minute=0, tz=UTC):
    """absolute test moments; the machine's current time is never used."""
    return datetime(2026, 10, day, hour, minute, tzinfo=tz)


# the query window: one week, Monday 2026-10-12 00:00 UTC to Monday 2026-10-19 00:00 UTC
WINDOW_START = at(12)
WINDOW_END = at(19)


def new_enforcer_from_text(model_text):
    m = Model()
    m.load_model_from_text(model_text)
    return casbin.Enforcer(m)


class TestTemporalIntervals(TestCase):
    def build_enforcer(self):
        """overlapping inheritance paths, a zero-length link and a short deny."""
        e = casbin.Enforcer(get_examples("rbac_with_temporal_intervals_model.conf"))

        # path 1: alice -> ops -> admin, valid during the first half of the week
        e.add_grouping_policy("alice", "ops")
        e.add_named_link_validity_interval("g", "alice", "ops", at(12), at(14))
        e.add_grouping_policy("ops", "admin")
        # path 2: alice -> admin directly, chaining right after path 1 ends
        e.add_grouping_policy("alice", "admin")
        e.add_named_link_validity_interval("g", "alice", "admin", at(14), at(16))
        # path 3: alice -> auditor, overlapping with both other paths
        e.add_grouping_policy("alice", "auditor")
        e.add_named_link_validity_interval("g", "alice", "auditor", at(13), at(15))
        # zero-length link: valid at no point in time
        e.add_grouping_policy("alice", "zero_role")
        e.add_named_link_validity_interval("g", "alice", "zero_role", at(15, 8), at(15, 8))

        e.add_policy("admin", "data1", "read", "allow")
        e.add_policy("auditor", "data1", "read", "allow")
        e.add_named_policy_validity_interval("p", ("auditor", "data1", "read", "allow"), at(13), at(15))
        # a short deny punches a two-hour hole into the allow intervals
        e.add_policy("admin", "data1", "read", "deny")
        e.add_named_policy_validity_interval("p", ("admin", "data1", "read", "deny"), at(13, 12), at(13, 14))
        e.add_policy("zero_role", "data1", "read", "allow")
        # direct permission, no role inheritance involved
        e.add_policy("alice", "data1", "write", "allow")
        e.add_named_policy_validity_interval("p", ("alice", "data1", "write", "allow"), at(17), at(18))
        return e

    def change_points(self):
        return [
            WINDOW_START,
            at(13),
            at(13, 12),
            at(13, 14),
            at(14),
            at(15),
            at(15, 8),
            at(16),
            at(17),
            at(18),
            WINDOW_END,
        ]

    def assert_consistent_with_point_checks(self, e, rvals, intervals):
        """the interval answer must agree with point-in-time authorization
        right before, exactly at, and right after every change point."""
        for point in self.change_points():
            for moment in (point - EPSILON, point, point + EPSILON):
                expected = contains_moment(intervals, moment)
                actual = e.is_allowed_at(moment, *rvals)
                self.assertEqual(expected, actual, f"mismatch at {moment.isoformat()} for {rvals}")
    def test_allowed_intervals_overlapping_paths_and_short_deny(self):
        e = self.build_enforcer()

        intervals = e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
        self.assertEqual(intervals, [(at(12), at(13, 12)), (at(13, 14), at(16))])
        self.assert_consistent_with_point_checks(e, ("alice", "data1", "read"), intervals)

    def test_allowed_intervals_direct_permission(self):
        e = self.build_enforcer()

        intervals = e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "write")
        self.assertEqual(intervals, [(at(17), at(18))])
        self.assert_consistent_with_point_checks(e, ("alice", "data1", "write"), intervals)

    def test_allowed_intervals_empty(self):
        e = self.build_enforcer()
        self.assertEqual([], e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data2", "read"))
        self.assertEqual([], e.get_allowed_intervals(WINDOW_START, WINDOW_END, "bob", "data1", "read"))
        self.assertEqual([], e.get_allowed_intervals(at(15), at(15), "alice", "data1", "read"))

    def test_allowed_intervals_sorted_non_overlapping_and_clipped(self):
        e = self.build_enforcer()
        intervals = e.get_allowed_intervals(at(13), at(15), "alice", "data1", "read")
        self.assertEqual(intervals, [(at(13), at(13, 12)), (at(13, 14), at(15))])
        for (start, end), (next_start, _) in zip(intervals, intervals[1:]):
            self.assertLess(start, end)
            self.assertLess(end, next_start)

    def test_timezone_aware_inputs_in_any_timezone(self):
        tz_cn = timezone(timedelta(hours=8))
        e = casbin.Enforcer(get_examples("rbac_with_temporal_intervals_model.conf"))
        e.add_grouping_policy("alice", "admin")
        e.add_named_link_validity_interval("g", "alice", "admin", at(14, 8, tz=tz_cn), at(16, 8, tz=tz_cn))
        e.add_policy("admin", "data1", "read", "allow")

        intervals = e.get_allowed_intervals(
            "2026-10-12T08:00:00+08:00",
            "2026-10-19T08:00:00+08:00",
            "alice",
            "data1",
            "read",
        )
        self.assertEqual(intervals, [(at(14), at(16))])
        self.assertTrue(e.is_allowed_at("2026-10-15T10:00:00+08:00", "alice", "data1", "read"))
        self.assertFalse(e.is_allowed_at("2026-10-17T08:00:00+08:00", "alice", "data1", "read"))
    def test_naive_or_reversed_times_rejected(self):
        e = self.build_enforcer()
        with self.assertRaises(ValueError):
            e.get_allowed_intervals(datetime(2026, 10, 12), WINDOW_END, "alice", "data1", "read")
        with self.assertRaises(ValueError):
            e.get_allowed_intervals("2026-10-12 00:00:00", WINDOW_END, "alice", "data1", "read")
        with self.assertRaises(ValueError):
            e.get_allowed_intervals(WINDOW_END, WINDOW_START, "alice", "data1", "read")
        with self.assertRaises(ValueError):
            e.is_allowed_at(datetime(2026, 10, 13), "alice", "data1", "read")
        with self.assertRaises(ValueError):
            e.add_named_link_validity_interval("g", "alice", "admin", datetime(2026, 10, 12), at(13))
        with self.assertRaises(ValueError):
            e.add_named_policy_validity_interval("p", ("admin", "data1", "read", "allow"), at(14), at(13))

    def test_no_validity_intervals_means_whole_window(self):
        e = casbin.Enforcer(get_examples("rbac_with_temporal_intervals_model.conf"))
        e.add_grouping_policy("alice", "admin")
        e.add_policy("admin", "data1", "read", "allow")

        intervals = e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
        self.assertEqual(intervals, [(WINDOW_START, WINDOW_END)])
        self.assertTrue(e.is_allowed_at(at(12), "alice", "data1", "read"))
        self.assertTrue(e.is_allowed_at(at(18, 23), "alice", "data1", "read"))

    def test_zero_length_policy_interval_never_valid(self):
        e = casbin.Enforcer(get_examples("rbac_with_temporal_intervals_model.conf"))
        e.add_policy("alice", "data1", "read", "allow")
        e.add_named_policy_validity_interval("p", ("alice", "data1", "read", "allow"), at(15, 8), at(15, 8))

        self.assertEqual([], e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read"))
        self.assertFalse(e.is_allowed_at(at(15, 8), "alice", "data1", "read"))

    def test_remove_validity_intervals(self):
        e = casbin.Enforcer(get_examples("rbac_with_temporal_intervals_model.conf"))
        e.add_grouping_policy("alice", "admin")
        e.add_named_link_validity_interval("g", "alice", "admin", at(12), at(14))
        e.add_policy("admin", "data1", "read", "allow")
        e.add_named_policy_validity_interval("p", ("admin", "data1", "read", "allow"), at(13), at(15))

        intervals = e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
        self.assertEqual(intervals, [(at(13), at(14))])

        self.assertTrue(e.remove_named_link_validity_interval("g", "alice", "admin"))
        self.assertFalse(e.remove_named_link_validity_interval("g", "alice", "admin"))
        intervals = e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
        self.assertEqual(intervals, [(at(13), at(15))])

        self.assertTrue(e.remove_named_policy_validity_interval("p", ("admin", "data1", "read", "allow")))
        self.assertFalse(e.remove_named_policy_validity_interval("p", ("admin", "data1", "read", "allow")))
        intervals = e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
        self.assertEqual(intervals, [(WINDOW_START, WINDOW_END)])
    def test_allow_override_ignores_deny_rules(self):
        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""
        e = new_enforcer_from_text(model_text)
        e.add_policy("alice", "data1", "read", "allow")
        e.add_policy("alice", "data1", "read", "deny")
        e.add_named_policy_validity_interval("p", ("alice", "data1", "read", "deny"), at(13), at(14))

        intervals = e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
        self.assertEqual(intervals, [(WINDOW_START, WINDOW_END)])
        self.assertTrue(e.is_allowed_at(at(13, 12), "alice", "data1", "read"))

    def test_deny_override(self):
        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = !some(where (p.eft == deny))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""
        e = new_enforcer_from_text(model_text)
        e.add_policy("alice", "data1", "read", "deny")
        e.add_named_policy_validity_interval("p", ("alice", "data1", "read", "deny"), at(13), at(14))

        intervals = e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
        self.assertEqual(intervals, [(WINDOW_START, at(13)), (at(14), WINDOW_END)])
        for moment in (at(13) - EPSILON, at(13), at(14) - EPSILON, at(14), at(14) + EPSILON):
            self.assertEqual(
                contains_moment(intervals, moment),
                e.is_allowed_at(moment, "alice", "data1", "read"),
                f"mismatch at {moment.isoformat()}",
            )

    def test_priority_effect(self):
        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""
        e = new_enforcer_from_text(model_text)
        # higher priority because it is listed first: a short deny on top of a permanent allow
        e.add_policy("alice", "data1", "read", "deny")
        e.add_named_policy_validity_interval("p", ("alice", "data1", "read", "deny"), at(13, 12), at(13, 14))
        e.add_policy("alice", "data1", "read", "allow")

        intervals = e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
        self.assertEqual(intervals, [(WINDOW_START, at(13, 12)), (at(13, 14), WINDOW_END)])
        self.assertFalse(e.is_allowed_at(at(13, 13), "alice", "data1", "read"))
        self.assertTrue(e.is_allowed_at(at(13, 15), "alice", "data1", "read"))
    def test_link_condition_functions_rejected(self):
        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _, (_, _)

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""
        from casbin.persist.adapters import StringAdapter

        m = Model()
        m.load_model_from_text(model_text)
        e = casbin.Enforcer(m, StringAdapter("p, admin, data1, read\ng, alice, admin, _, _"))
        self.assertTrue(e.add_named_link_condition_func("g", "alice", "admin", lambda *args: True))
        with self.assertRaises(RuntimeError):
            e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
        with self.assertRaises(RuntimeError):
            e.is_allowed_at(at(13), "alice", "data1", "read")

    def test_time_match_in_matcher_rejected(self):
        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act && timeMatch("2026-01-01 00:00:00", "2027-01-01 00:00:00")
"""
        e = new_enforcer_from_text(model_text)
        e.add_policy("alice", "data1", "read")
        with self.assertRaises(RuntimeError):
            e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")

    def test_custom_matcher_function_rejected(self):
        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && myTimeFunc(r.obj)
"""
        e = new_enforcer_from_text(model_text)
        e.add_function("myTimeFunc", lambda obj: True)
        e.add_policy("alice", "data1", "read")
        with self.assertRaises(RuntimeError):
            e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")

    def test_eval_in_matcher_rejected(self):
        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && eval("r.obj == p.obj")
"""
        e = new_enforcer_from_text(model_text)
        e.add_policy("alice", "data1", "read")
        with self.assertRaises(RuntimeError):
            e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")

    def test_domain_role_definition_rejected(self):
        model_text = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act
"""
        e = new_enforcer_from_text(model_text)
        e.add_policy("alice", "data1", "read")
        with self.assertRaises(RuntimeError):
            e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "dom1", "data1", "read")

    def test_subject_priority_effect_rejected(self):
        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = subjectPriority(p.eft) || deny

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""
        e = new_enforcer_from_text(model_text)
        e.add_policy("alice", "data1", "read", "allow")
        with self.assertRaises(RuntimeError):
            e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
    def test_policy_without_eft_column_defaults_to_allow(self):
        model_text = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch2(r.obj, p.obj) && r.act == p.act
"""
        e = new_enforcer_from_text(model_text)
        e.add_policy("alice", "/data/:resource", "read")
        e.add_named_policy_validity_interval("p", ("alice", "/data/:resource", "read"), at(13), at(15))

        intervals = e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "/data/1", "read")
        self.assertEqual(intervals, [(at(13), at(15))])
        self.assertTrue(e.is_allowed_at(at(14), "alice", "/data/1", "read"))
        self.assertFalse(e.is_allowed_at(at(16), "alice", "/data/1", "read"))
