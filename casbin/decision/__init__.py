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

"""Structured authorization decisions with policy obligations.

This package is intentionally side-effect free: it evaluates policies and
describes the obligations that the calling application must carry out
(masking a field, recording an audit event, ...), but it never performs
those actions itself.
"""

from .decision import (
    Decision,
    DecisionEffect,
    ObligationConflict,
    OBLIGATION_UNION,
    OBLIGATION_INTERSECTION,
    OBLIGATION_CONSENSUS,
    parse_obligation_definition,
    split_obligation_value,
    merge_obligations,
)

__all__ = [
    "Decision",
    "DecisionEffect",
    "ObligationConflict",
    "OBLIGATION_UNION",
    "OBLIGATION_INTERSECTION",
    "OBLIGATION_CONSENSUS",
    "parse_obligation_definition",
    "split_obligation_value",
    "merge_obligations",
]
