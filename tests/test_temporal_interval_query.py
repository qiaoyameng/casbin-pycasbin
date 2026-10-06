# Copyright 2021 The casbin Authors. All Rights Reserved.
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

from datetime import datetime, timedelta, timezone
from unittest import TestCase

import casbin
from casbin.persist.adapters.string_adapter import StringAdapter

UTC = timezone.utc

# one bounded query window: 2026-10-05 (Mon) 00:00 UTC .. 2026-10-12 (Mon) 00:00 UTC
WINDOW_START = datetime(2026, 10, 5, 0, 0, tzinfo=UTC)
WINDOW_END = datetime(2026, 10, 12, 0, 0, tzinfo=UTC)

RBAC_TEMPORAL_MODEL = """
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

RBAC_TEMPORAL_DENY_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _, (_, _)

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""

BASIC_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""

RBAC_TEMPORAL_DOMAIN_MODEL = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _, (_, _)

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
"""


def at(day, hour=0, minute=0):
    """absolute moment inside the query window, in UTC"""
    return datetime(2026, 10, day, hour, minute, tzinfo=UTC)


def get_enforcer(model_text, policy_text):
    model = casbin.Model()
    model.load_model_from_text(model_text)
    return casbin.Enforcer(model, StringAdapter(policy_text))


class TestTemporalIntervalQuery(TestCase):
    def assert_intervals(self, e, rvals, expected, window_start=WINDOW_START, window_end=WINDOW_END):
        """checks the exact interval result and cross-checks point-in-time
        enforcement before, at, and after every change point."""
        intervals = e.get_allowed_intervals(window_start, window_end, *rvals)
        self.assertEqual(expected, intervals)

        # sorted and non-overlapping
        for (s1, e1), (s2, e2) in zip(intervals, intervals[1:]):
            self.assertLess(s1, e1)
            self.assertLessEqual(e1, s2)

        def expected_at(t):
            return any(s <= t < en for s, en in intervals)

        change_points = {window_start, window_end}
        for s, en in intervals:
            change_points.add(s)
            change_points.add(en)

        second = timedelta(seconds=1)
        for point in sorted(change_points):
            for moment in (point - second, point, point + second):
                if window_start <= moment < window_end:
                    self.assertEqual(
                        expected_at(moment),
                        e.enforce_at(moment, *rvals),
                        f"point-in-time mismatch at {moment.isoformat()}",
                    )

        # sample the middle of every elementary segment as well
        sorted_points = sorted(change_points)
        for left, right in zip(sorted_points, sorted_points[1:]):
            if left < right:
                middle = left + (right - left) / 2
                self.assertEqual(expected_at(middle), e.enforce_at(middle, *rvals))

        return intervals

    def test_overlapping_paths_union(self):
        e = get_enforcer(
            RBAC_TEMPORAL_MODEL,
            """
p, role_a, data1, read
p, role_b, data1, read
g, alice, role_a, _, _
g, alice, role_b, _, _
""",
        )
        e.add_named_link_validity_interval("g", "alice", "role_a", at(5, 9), at(7, 18))
        e.add_named_link_validity_interval("g", "alice", "role_b", at(6, 9), at(8, 12))

        # two overlapping inheritance paths merge into one continuous interval
        self.assert_intervals(e, ("alice", "data1", "read"), [(at(5, 9), at(8, 12))])
        # a different action is never allowed
        self.assert_intervals(e, ("alice", "data1", "write"), [])

    def test_inheritance_path_requires_all_links_valid(self):
        e = get_enforcer(
            RBAC_TEMPORAL_MODEL,
            """
p, role_b, data2, read
g, alice, role_a, _, _
g, role_a, role_b, _, _
""",
        )
        e.add_named_link_validity_interval("g", "alice", "role_a", at(5, 10), at(10, 20))
        e.add_named_link_validity_interval("g", "role_a", "role_b", at(6, 12), at(7, 15))

        # along one path both links must be valid simultaneously: intersection
        self.assert_intervals(e, ("alice", "data2", "read"), [(at(6, 12), at(7, 15))])

    def test_adjacent_paths_chain_into_single_interval(self):
        e = get_enforcer(
            RBAC_TEMPORAL_MODEL,
            """
p, role_x, data3, read
p, role_y, data3, read
g, alice, role_x, _, _
g, alice, role_y, _, _
""",
        )
        e.add_named_link_validity_interval("g", "alice", "role_x", at(5, 9), at(6, 11))
        e.add_named_link_validity_interval("g", "alice", "role_y", at(6, 11), at(7, 13))

        # touching half-open intervals chain without a gap
        self.assert_intervals(e, ("alice", "data3", "read"), [(at(5, 9), at(7, 13))])

    def test_zero_length_interval_grants_nothing(self):
        e = get_enforcer(
            RBAC_TEMPORAL_MODEL,
            """
p, role_z, data4, read
g, alice, role_z, _, _
""",
        )
        e.add_named_link_validity_interval("g", "alice", "role_z", at(6, 14), at(6, 14))

        self.assert_intervals(e, ("alice", "data4", "read"), [])
        self.assertFalse(e.enforce_at(at(6, 14), "alice", "data4", "read"))

    def test_short_deny_punches_hole(self):
        e = get_enforcer(
            RBAC_TEMPORAL_DENY_MODEL,
            """
p, alice, data1, read, allow
p, alice, data1, read, deny
""",
        )
        e.set_named_policy_validity_interval("p", ["alice", "data1", "read", "allow"], at(5), at(10))
        e.set_named_policy_validity_interval("p", ["alice", "data1", "read", "deny"], at(7, 12), at(7, 13))

        # the allow rule is valid all week; a one-hour deny interrupts it
        self.assert_intervals(
            e,
            ("alice", "data1", "read"),
            [(at(5), at(7, 12)), (at(7, 13), at(10))],
        )

    def test_policy_row_validity_on_basic_model(self):
        e = get_enforcer(
            BASIC_MODEL,
            """
p, alice, data1, read
p, bob, data2, read
""",
        )
        e.set_named_policy_validity_interval("p", ["alice", "data1", "read"], at(6, 9), at(6, 17))
        # bob's rule carries no validity interval: always active
        self.assert_intervals(e, ("alice", "data1", "read"), [(at(6, 9), at(6, 17))])
        self.assert_intervals(e, ("bob", "data2", "read"), [(WINDOW_START, WINDOW_END)])

    def test_unbounded_validity_ends(self):
        e = get_enforcer(
            BASIC_MODEL,
            """
p, alice, data1, read
p, carol, data3, read
""",
        )
        e.set_named_policy_validity_interval("p", ["alice", "data1", "read"], None, at(7))
        e.set_named_policy_validity_interval("p", ["carol", "data3", "read"], at(8, 12), "_")

        self.assert_intervals(e, ("alice", "data1", "read"), [(WINDOW_START, at(7))])
        self.assert_intervals(e, ("carol", "data3", "read"), [(at(8, 12), WINDOW_END)])

    def test_timezone_aware_inputs(self):
        e = get_enforcer(
            BASIC_MODEL,
            """
p, alice, data1, read
""",
        )
        # 09:00-17:00 at +08:00 == 01:00-09:00 UTC
        e.set_named_policy_validity_interval(
            "p",
            ["alice", "data1", "read"],
            "2026-10-06T09:00:00+08:00",
            "2026-10-06T17:00:00+08:00",
        )
        intervals = e.get_allowed_intervals(
            "2026-10-06T00:00:00+08:00",
            "2026-10-07T00:00:00+08:00",
            "alice",
            "data1",
            "read",
        )
        self.assertEqual(
            [(datetime(2026, 10, 6, 1, 0, tzinfo=UTC), datetime(2026, 10, 6, 9, 0, tzinfo=UTC))],
            intervals,
        )
        self.assertTrue(e.enforce_at("2026-10-06T12:00:00+08:00", "alice", "data1", "read"))
        self.assertFalse(e.enforce_at("2026-10-06T20:00:00+08:00", "alice", "data1", "read"))

    def test_domain_temporal_model(self):
        e = get_enforcer(
            RBAC_TEMPORAL_DOMAIN_MODEL,
            """
p, data2_admin, domain2, data2, read
g, alice, data2_admin, domain2, _, _
""",
        )
        e.add_named_domain_link_validity_interval("g", "alice", "data2_admin", "domain2", at(6, 9), at(9, 18))

        self.assert_intervals(e, ("alice", "domain2", "data2", "read"), [(at(6, 9), at(9, 18))])
        self.assert_intervals(e, ("alice", "domain1", "data2", "read"), [])

    def test_custom_condition_func_rejected(self):
        e = get_enforcer(
            RBAC_TEMPORAL_MODEL,
            """
p, role_a, data1, read
g, alice, role_a, _, _
""",
        )
        e.add_named_link_condition_func("g", "alice", "role_a", lambda *args: True)

        with self.assertRaises(RuntimeError):
            e.get_allowed_intervals(WINDOW_START, WINDOW_END, "alice", "data1", "read")
        with self.assertRaises(RuntimeError):
            e.enforce_at(at(6), "alice", "data1", "read")

        # ordinary enforcement still uses the custom function
        self.assertTrue(e.enforce("alice", "data1", "read"))

    def test_naive_time_rejected(self):
        e = get_enforcer(
            BASIC_MODEL,
            """
p, alice, data1, read
""",
        )
        naive = datetime(2026, 10, 6, 9, 0)
        with self.assertRaises(ValueError):
            e.get_allowed_intervals(naive, WINDOW_END, "alice", "data1", "read")
        with self.assertRaises(ValueError):
            e.get_allowed_intervals("2026-10-05 00:00:00", "2026-10-12 00:00:00", "alice", "data1", "read")
        with self.assertRaises(ValueError):
            e.enforce_at(naive, "alice", "data1", "read")
        with self.assertRaises(ValueError):
            e.set_named_policy_validity_interval("p", ["alice", "data1", "read"], naive, at(7))

    def test_window_validation(self):
        e = get_enforcer(
            BASIC_MODEL,
            """
p, alice, data1, read
""",
        )
        with self.assertRaises(ValueError):
            e.get_allowed_intervals(WINDOW_END, WINDOW_START, "alice", "data1", "read")
        with self.assertRaises(ValueError):
            e.get_allowed_intervals("_", WINDOW_END, "alice", "data1", "read")
        # a zero-length window contains no time at all
        self.assertEqual([], e.get_allowed_intervals(at(6), at(6), "alice", "data1", "read"))

    def test_invalid_validity_interval_rejected(self):
        e = get_enforcer(
            BASIC_MODEL,
            """
p, alice, data1, read
""",
        )
        with self.assertRaises(ValueError):
            e.set_named_policy_validity_interval("p", ["alice", "data1", "read"], at(7), at(6))
        with self.assertRaises(ValueError):
            e.set_named_policy_validity_interval("p", ["alice", "data1", "read"], "not-a-time", at(6))
        with self.assertRaises(ValueError):
            e.set_named_policy_validity_interval("p", ["alice", "data9", "read"], at(6), at(7))

    def test_intervals_clipped_to_window(self):
        e = get_enforcer(
            BASIC_MODEL,
            """
p, alice, data1, read
""",
        )
        e.set_named_policy_validity_interval("p", ["alice", "data1", "read"], at(1), at(20))
        self.assert_intervals(e, ("alice", "data1", "read"), [(WINDOW_START, WINDOW_END)])
