import pytest

from casbin.relations import (
    ComputedUserset,
    Difference,
    Intersection,
    RelationModel,
    RelationSpec,
    This,
    TupleStore,
    TupleToUserset,
    Union,
    direct_users,
    object_of,
    userset_of,
)


def build_model():
    """Document/folder/team model used across the authorization tests."""

    return RelationModel(
        [
            # folder.viewer = direct members + viewers reached through parent folders
            RelationSpec(
                "folder",
                "viewer",
                Union(This(), TupleToUserset("parent", "viewer")),
                (direct_users(), userset_of("folder", "viewer")),
            ),
            RelationSpec("folder", "editor", This(), (direct_users(),)),
            RelationSpec("folder", "parent", This(), (object_of("folder"),)),
            RelationSpec("document", "parent", This(), (object_of("folder"),)),
            RelationSpec("document", "blocked", This(), (direct_users(),)),
            # document.viewer = (direct shares + parent folder viewers) - blocked
            RelationSpec(
                "document",
                "viewer",
                Difference(
                    Union(This(), TupleToUserset("parent", "viewer")),
                    ComputedUserset("blocked"),
                ),
                (direct_users(), userset_of("folder", "viewer")),
            ),
            # document.reviewer = direct viewers intersected with parent folder editors
            RelationSpec(
                "document",
                "reviewer",
                Intersection(
                    ComputedUserset("viewer"),
                    TupleToUserset("parent", "editor"),
                ),
                (),
            ),
            # teams nest positively and may contain cycles
            RelationSpec(
                "team",
                "member",
                Union(This(), TupleToUserset("member", "member")),
                (direct_users(), object_of("team")),
            ),
        ]
    )


@pytest.fixture
def model():
    return build_model()


@pytest.fixture
def store(model):
    return TupleStore(model=model)
