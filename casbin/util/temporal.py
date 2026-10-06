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

"""Exact interval algebra on half-open, timezone-aware time intervals.

An interval is a ``(start, end)`` tuple of aware ``datetime`` objects with
``start < end``; the start is inclusive and the end is exclusive.  Interval
lists are always kept sorted and non-overlapping, so every operation is an
exact set operation over the time line rather than a sampling approximation.
"""

from datetime import datetime


def ensure_aware_datetime(value, name="time"):
    """returns ``value`` as a timezone-aware ``datetime``.

    Accepts aware ``datetime`` objects or ISO-8601 strings carrying a
    timezone offset (``Z`` is accepted as UTC).  Naive datetimes are
    rejected so that authorization windows never depend on the machine's
    local timezone or current time.
    """
    if isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            value = datetime.fromisoformat(text)
        except ValueError:
            raise ValueError(f"{name} must be an ISO-8601 timestamp with a timezone offset, got {value!r}")
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime or an ISO-8601 string, got {type(value).__name__}")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{name} must be timezone-aware, got naive datetime {value!r}")
    return value


def validate_interval(start, end):
    """validates a half-open interval and returns it as an (start, end) tuple.

    Zero-length intervals (``start == end``) are allowed; they are valid at
    no point in time.
    """
    start = ensure_aware_datetime(start, "start")
    end = ensure_aware_datetime(end, "end")
    if end < start:
        raise ValueError(f"interval end {end!r} must not be before start {start!r}")
    return (start, end)


def normalize_intervals(intervals):
    """sorts intervals, drops empty ones and merges overlapping or adjacent ones."""
    sorted_intervals = sorted((start, end) for start, end in intervals if start < end)
    merged = []
    for start, end in sorted_intervals:
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def union_intervals(*interval_lists):
    """returns the union of any number of interval lists, normalized."""
    return normalize_intervals([interval for intervals in interval_lists for interval in intervals])


def intersect_intervals(a, b):
    """returns the intersection of two normalized interval lists."""
    result = []
    i = j = 0
    while i < len(a) and j < len(b):
        start = max(a[i][0], b[j][0])
        end = min(a[i][1], b[j][1])
        if start < end:
            result.append((start, end))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return result


def subtract_intervals(a, b):
    """returns the parts of ``a`` not covered by ``b`` (both normalized)."""
    result = []
    for start, end in a:
        cursor = start
        for b_start, b_end in b:
            if b_end <= cursor:
                continue
            if b_start >= end:
                break
            if b_start > cursor:
                result.append((cursor, b_start))
            cursor = max(cursor, b_end)
            if cursor >= end:
                break
        if cursor < end:
            result.append((cursor, end))
    return result


def complement_intervals(intervals, window):
    """returns the parts of the ``window`` interval not covered by ``intervals``."""
    return subtract_intervals([window], intervals)


def clip_intervals(intervals, window):
    """clips intervals to the half-open ``window`` interval."""
    return intersect_intervals(normalize_intervals(intervals), [window])


def contains_moment(intervals, moment):
    """returns True if the half-open intervals contain ``moment``."""
    return any(start <= moment < end for start, end in intervals)
