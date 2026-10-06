# Copyright 2024 The casbin Authors. All Rights Reserved.
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

import pytest

from casbin.relationship import (
    User,
    ObjectRef,
    UsersetRef,
    parse_subject,
    RelationshipTuple,
    InvalidSubjectError,
    InvalidTupleError,
)


class TestSubjects:
    def test_user_is_distinct_from_object(self):
        assert parse_subject("alice") == User("alice")
        assert parse_subject("alice") != ObjectRef("user", "alice")

    def test_object_and_userset_parsing(self):
        assert parse_subject("folder:f1") == ObjectRef("folder", "f1")
        assert parse_subject("folder:f1#viewer") == UsersetRef("folder", "f1", "viewer")

    def test_typed_subjects_pass_through(self):
        ref = UsersetRef("team", "eng", "member")
        assert parse_subject(ref) is ref

    def test_userset_object_accessor(self):
        assert UsersetRef("team", "eng", "member").object == ObjectRef("team", "eng")

    def test_invalid_subjects(self):
        with pytest.raises(InvalidSubjectError):
            parse_subject("")
        with pytest.raises(InvalidSubjectError):
            parse_subject("type:#rel")
        with pytest.raises(InvalidSubjectError):
            parse_subject("type:id#")

    def test_tuple_fields(self):
        t = RelationshipTuple("document", "1", "viewer", "alice")
        assert t.key == ("document", "1", "viewer")
        assert t.subject == User("alice")

    def test_tuple_string_parse(self):
        t = RelationshipTuple.parse("document:1#viewer@folder:f1#viewer")
        assert t.object_type == "document"
        assert t.object_id == "1"
        assert t.relation == "viewer"
        assert t.subject == UsersetRef("folder", "f1", "viewer")

    def test_tuple_string_parse_direct_user(self):
        t = RelationshipTuple.parse("document:1#viewer@alice")
        assert t.subject == User("alice")

    def test_tuple_string_invalid(self):
        with pytest.raises(InvalidTupleError):
            RelationshipTuple.parse("garbage")
