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

from datetime import datetime, timedelta, timezone
from unittest import TestCase

from casbin.util import temporal

UTC = timezone.utc


def at(hour):
    return datetime(2026, 10, 12, hour, tzinfo=UTC)


class TestTemporalUtil(TestCase):
    def test_normalize_merges_overlapping_adjacent_and_drops_empty(self):
        intervals = [(at(2), at(3)), (at(0), at(1)), (at(1), at(2)), (at(5), at(5)), (at(2), at(4))]
        self.assertEqual(temporal.normalize_intervals(intervals), [(at(0), at(4))])

    def test_intersect_intervals(self):
        a = [(at(0), at(4)), (at(6), at(8))]
        b = [(at(2), at(7))]
        self.assertEqual(temporal.intersect_intervals(a, b), [(at(2), at(4)), (at(6), at(7))])
        self.assertEqual(temporal.intersect_intervals(a, []), [])

    def test_subtract_intervals(self):
        a = [(at(0), at(10))]
        b = [(at(2), at(4)), (at(6), at(7)), (at(9), at(12))]
        self.assertEqual(
            temporal.subtract_intervals(a, b),
            [(at(0), at(2)), (at(4), at(6)), (at(7), at(9))],
        )

    def test_complement_intervals(self):
        self.assertEqual(
            temporal.complement_intervals([(at(2), at(3))], (at(0), at(5))),
            [(at(0), at(2)), (at(3), at(5))],
        )
        self.assertEqual(temporal.complement_intervals([], (at(0), at(5))), [(at(0), at(5))])

    def test_contains_moment_is_half_open(self):
        intervals = [(at(1), at(2))]
        self.assertFalse(temporal.contains_moment(intervals, at(1) - timedelta(microseconds=1)))
        self.assertTrue(temporal.contains_moment(intervals, at(1)))
        self.assertFalse(temporal.contains_moment(intervals, at(2)))

    def test_ensure_aware_datetime(self):
        aware = temporal.ensure_aware_datetime("2026-10-12T08:00:00+08:00")
        self.assertEqual(aware, datetime(2026, 10, 12, 0, 0, tzinfo=UTC))
        self.assertEqual(temporal.ensure_aware_datetime("2026-10-12T00:00:00Z"), datetime(2026, 10, 12, tzinfo=UTC))
        with self.assertRaises(ValueError):
            temporal.ensure_aware_datetime(datetime(2026, 10, 12))
        with self.assertRaises(ValueError):
            temporal.ensure_aware_datetime("2026-10-12 00:00:00")
        with self.assertRaises(TypeError):
            temporal.ensure_aware_datetime(12345)

    def test_validate_interval(self):
        self.assertEqual(temporal.validate_interval(at(1), at(1)), (at(1), at(1)))
        with self.assertRaises(ValueError):
            temporal.validate_interval(at(2), at(1))
