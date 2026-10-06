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

from datetime import datetime, timezone

__all__ = [
    "MIN_TIME",
    "MAX_TIME",
    "parse_time",
    "parse_required_time",
    "parse_validity_interval",
    "merge_intervals",
]

# Internal sentinels for unbounded interval ends. They never leak into query
# results because results are always clipped to the (bounded) query window.
MIN_TIME = datetime.min.replace(tzinfo=timezone.utc)
MAX_TIME = datetime.max.replace(tzinfo=timezone.utc)


def parse_time(value, name="time"):
    """parses a timezone-aware absolute moment.

    Accepts a datetime object or an ISO 8601 string, both of which must carry
    timezone information. None or "_" means "unbounded" and yields None.
    The machine clock is never consulted.
    """
    if value is None or value == "_":
        return None

    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            raise ValueError(f"{name} must be an ISO 8601 timestamp with timezone, got {value!r}")
    else:
        raise TypeError(f"{name} must be a datetime or an ISO 8601 string, got {type(value).__name__}")

    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError(f"{name} must carry timezone information, got {value!r}")

    return moment.astimezone(timezone.utc)


def parse_required_time(value, name="time"):
    """parses a moment that must be concrete (not unbounded)."""
    moment = parse_time(value, name)
    if moment is None:
        raise ValueError(f"{name} must be a concrete timezone-aware moment, got {value!r}")
    return moment


def parse_validity_interval(start, end):
    """parses a half-open validity interval [start, end).

    Either end may be None or "_" to leave it unbounded. A zero-length
    interval (start == end) is valid and never contains any moment.
    """
    start_moment = parse_time(start, "validity start")
    end_moment = parse_time(end, "validity end")

    start_moment = start_moment if start_moment is not None else MIN_TIME
    end_moment = end_moment if end_moment is not None else MAX_TIME

    if start_moment > end_moment:
        raise ValueError(f"validity interval start {start!r} is after end {end!r}")

    return start_moment, end_moment


def merge_intervals(intervals):
    """merges half-open intervals into a sorted, non-overlapping list.

    Empty intervals (start >= end) are dropped and touching intervals such as
    [a, b) and [b, c) are coalesced into [a, c).
    """
    ordered = sorted((start, end) for start, end in intervals if start < end)
    merged = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged
