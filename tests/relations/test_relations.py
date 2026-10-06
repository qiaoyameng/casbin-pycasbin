import pytest

from casbin.relations import (
    ComputedUserset,
    Difference,
    Entity,
    Intersection,
    ObjectType,
    Relation,
    RelationChecker,
    RelationModel,
    RelationModelError,
    RelationSpec,
    This,
    TupleStore,
    TupleToUserset,
    Union,
    User,
    direct_users,
    new_relation_enforcer,
    object_of,
    tuple_from_string,
    user,
    userset_of,
)
from tests.relations.conftest import build_model


def load(store, tuples):
    for value in tuples:
        store.add(value)


# ---------------------------------------------------------------------------
# identity types stay distinct
# ---------------------------------------------------------------------------

def test_types_relations_and_users_are_distinct():
    assert ObjectType("document") != Relation("document")
    assert str(Entity(ObjectType("document"), "plan")) == "document:plan"
    assert str(User("alice")) == "user:alice"
    assert user("alice") == user("user:alice")
    assert Entity(ObjectType("user"), "alice") != User("alice")


def test_tuple_string_roundtrip():
    rel_tuple = tuple_from_string("document:plan#viewer@user:alice")
    assert str(rel_tuple) == "document:plan#viewer@user:alice"
    assert rel_tuple.subject.user == User("alice")

    rel_tuple = tuple_from_string("document:plan#viewer@folder:root#viewer")
    assert rel_tuple.subject.userset.object.type_name == "folder"
    assert str(rel_tuple) == "document:plan#viewer@folder:root#viewer"

    with pytest.raises(ValueError):
        tuple_from_string("garbage")


# ---------------------------------------------------------------------------
# direct members and userset rewrites
# ---------------------------------------------------------------------------

def test_direct_members(model, store):
    load(store, ["document:plan#viewer@user:alice"])
    checker = RelationChecker(model, store)
    assert checker.check(User("alice"), "document:plan", "viewer")
    assert checker.check("alice", Entity(ObjectType("document"), "plan"), Relation("viewer"))
    assert not checker.check(User("bob"), "document:plan", "viewer")


def test_parent_folder_viewer_userset(model, store):
    load(store, [
        "folder:root#viewer@user:alice",
        "document:plan#parent@folder:root",
    ])
    checker = RelationChecker(model, store)
    assert checker.check("alice", "document:plan", "viewer")
    assert checker.userset_members("document:plan", "viewer") == frozenset({User("alice")})


def test_parent_folder_chain_with_positive_recursion(model, store):
    load(store, [
        "folder:root#parent@folder:home",
        "folder:home#viewer@user:alice",
        "document:plan#parent@folder:root",
    ])
    checker = RelationChecker(model, store)
    assert checker.check("alice", "folder:root", "viewer")
    assert checker.check("alice", "document:plan", "viewer")


def test_intersection_reviewer(model, store):
    load(store, [
        "folder:root#editor@user:alice",
        "folder:root#viewer@user:alice",
        "folder:root#viewer@user:bob",
        "document:plan#parent@folder:root",
        "document:plan#viewer@user:carol",
    ])
    checker = RelationChecker(model, store)
    assert checker.check("alice", "document:plan", "reviewer")
    assert not checker.check("bob", "document:plan", "reviewer")
    assert not checker.check("carol", "document:plan", "reviewer")


# ---------------------------------------------------------------------------
# diamond inheritance
# ---------------------------------------------------------------------------

def test_diamond_inheritance_union(model, store):
    # plan reaches root through two independent parent paths; membership
    # contributed by either branch must be granted.
    load(store, [
        "folder:left#parent@folder:root",
        "folder:right#parent@folder:root",
        "document:plan#parent@folder:left",
        "document:plan#parent@folder:right",
        "folder:root#viewer@user:alice",
    ])
    checker = RelationChecker(model, store)
    assert checker.check("alice", "document:plan", "viewer")


def test_diamond_each_branch_grants(model, store):
    load(store, [
        "folder:left#parent@folder:root",
        "folder:right#parent@folder:root",
        "document:plan#parent@folder:left",
        "document:plan#parent@folder:right",
        "folder:left#viewer@user:alice",
        "folder:right#viewer@user:bob",
    ])
    checker = RelationChecker(model, store)
    assert checker.check("alice", "document:plan", "viewer")
    assert checker.check("bob", "document:plan", "viewer")
    assert not checker.check("carol", "document:plan", "viewer")


# ---------------------------------------------------------------------------
# cyclic teams: positive recursion is allowed and reaches a fixed point
# ---------------------------------------------------------------------------

def test_cyclic_teams(model, store):
    load(store, [
        "team:a#member@team:b",
        "team:b#member@team:c",
        "team:c#member@team:a",
        "team:c#member@user:carol",
    ])
    checker = RelationChecker(model, store)
    assert checker.check("carol", "team:a", "member")
    assert checker.check("carol", "team:b", "member")
    assert checker.check("carol", "team:c", "member")
    assert not checker.check("dave", "team:a", "member")


def test_two_cycles_sharing_a_team(model, store):
    load(store, [
        "team:a#member@team:b",
        "team:b#member@team:a",
        "team:b#member@team:x",
        "team:x#member@team:b",
        "team:x#member@user:zoe",
    ])
    checker = RelationChecker(model, store)
    for team_id in ("a", "b", "x"):
        assert checker.check("zoe", f"team:{team_id}", "member")


# ---------------------------------------------------------------------------
# blocked overrides every inheritance path
# ---------------------------------------------------------------------------

def test_blocked_overrides_direct_share(model, store):
    load(store, [
        "document:plan#viewer@user:alice",
        "document:plan#blocked@user:alice",
    ])
    checker = RelationChecker(model, store)
    assert not checker.check("alice", "document:plan", "viewer")
    assert checker.check("alice", "document:plan", "blocked")


def test_blocked_overrides_multiple_inheritance_paths(model, store):
    # alice inherits through both diamond branches and a direct share;
    # blocked must deny anyway.
    load(store, [
        "folder:left#parent@folder:root",
        "folder:right#parent@folder:root",
        "document:plan#parent@folder:left",
        "document:plan#parent@folder:right",
        "folder:root#viewer@user:alice",
        "document:plan#viewer@user:alice",
        "document:plan#blocked@user:alice",
    ])
    checker = RelationChecker(model, store)
    assert not checker.check("alice", "document:plan", "viewer")

    members = checker.userset_members("document:plan", "viewer")
    assert User("alice") not in members

    # removing the block restores access via the fixed point recomputation
    store.remove("document:plan#blocked@user:alice")
    assert checker.check("alice", "document:plan", "viewer")


def test_blocked_does_not_affect_other_users(model, store):
    load(store, [
        "folder:root#viewer@user:alice",
        "folder:root#viewer@user:bob",
        "document:plan#parent@folder:root",
        "document:plan#blocked@user:alice",
    ])
    checker = RelationChecker(model, store)
    assert not checker.check("alice", "document:plan", "viewer")
    assert checker.check("bob", "document:plan", "viewer")


# ---------------------------------------------------------------------------
# definition-time rejection of negative recursion
# ---------------------------------------------------------------------------

def test_direct_negative_self_recursion_rejected():
    with pytest.raises(RelationModelError, match="negative recursion"):
        RelationModel([
            RelationSpec(
                "document", "viewer",
                Difference(This(), ComputedUserset("viewer")),
                (direct_users(),),
            )
        ])


def test_indirect_negative_recursion_rejected():
    # x = this - y, y = x  => x depends negatively on itself through y
    with pytest.raises(RelationModelError, match="negative recursion"):
        RelationModel([
            RelationSpec(
                "document", "x",
                Difference(This(), ComputedUserset("y")),
                (direct_users(),),
            ),
            RelationSpec(
                "document", "y",
                Union(This(), ComputedUserset("x")),
                (direct_users(),),
            ),
        ])


def test_negative_dependency_to_lower_stratum_is_allowed():
    # blocked is an independent relation (no cycle): stratified negation.
    model = build_model()
    assert model.get("document", "viewer") is not None


def test_undefined_reference_rejected():
    with pytest.raises(RelationModelError):
        RelationModel([
            RelationSpec("document", "viewer", ComputedUserset("nope"), (direct_users(),))
        ])


def test_negation_inside_union_still_rejected():
    # (this - viewer) | this still returns to viewer through subtraction
    with pytest.raises(RelationModelError):
        RelationModel([
            RelationSpec(
                "document", "viewer",
                Union(Difference(This(), ComputedUserset("viewer")), This()),
                (direct_users(),),
            )
        ])


# ---------------------------------------------------------------------------
# tuple validation against the typed model
# ---------------------------------------------------------------------------

def test_tuple_relation_must_exist(model, store):
    with pytest.raises(RelationModelError):
        store.add("document:plan#hacker@user:alice")


def test_tuple_subject_kind_checked(model, store):
    with pytest.raises(RelationModelError):
        # parent accepts bare folders, not users
        store.add("document:plan#parent@user:alice")
    with pytest.raises(RelationModelError):
        # blocked accepts direct users only, not objects
        store.add("document:plan#blocked@folder:root")
    store.add("document:plan#parent@folder:root")


# ---------------------------------------------------------------------------
# cache invalidation on store mutation
# ---------------------------------------------------------------------------

def test_checker_picks_up_mutations(model, store):
    checker = RelationChecker(model, store)
    store.add("document:plan#viewer@user:alice")
    assert checker.check("alice", "document:plan", "viewer")
    store.add("document:plan#blocked@user:alice")
    assert not checker.check("alice", "document:plan", "viewer")
    store.remove("document:plan#blocked@user:alice")
    assert checker.check("alice", "document:plan", "viewer")


# ---------------------------------------------------------------------------
# Casbin enforce integration
# ---------------------------------------------------------------------------

def test_casbin_enforce_uses_relation_model(model, store):
    load(store, [
        "folder:root#viewer@user:alice",
        "document:plan#parent@folder:root",
        "document:plan#blocked@user:alice",
        "document:plan#viewer@user:bob",
    ])
    enforcer = new_relation_enforcer(model, store)
    assert not enforcer.enforce("alice", "document:plan", "view")
    assert enforcer.enforce("user:bob", "document:plan", "view")
    assert not enforcer.enforce("carol", "document:plan", "view")
    # unknown relation name maps to itself and fails closed
    assert not enforcer.enforce("bob", "document:plan", "explode")


def test_casbin_enforce_custom_action_mapping(model, store):
    store.add("document:plan#viewer@user:alice")
    enforcer = new_relation_enforcer(model, store, {"read": "viewer"})
    assert enforcer.enforce("alice", "document:plan", "read")


def test_enforce_returns_plain_bool(model, store):
    store.add("document:plan#viewer@user:alice")
    enforcer = new_relation_enforcer(model, store)
    result = enforcer.enforce("alice", "document:plan", "view")
    assert result is True


# ---------------------------------------------------------------------------
# fixed-point edge cases
# ---------------------------------------------------------------------------

def test_long_positive_chain_converges(model, store):
    for i in range(30):
        store.add(f"folder:f{i}#parent@folder:f{i + 1}")
    store.add("folder:f30#viewer@user:alice")
    store.add("document:plan#parent@folder:f0")
    checker = RelationChecker(model, store)
    assert checker.check("alice", "document:plan", "viewer")


def test_nested_difference_allowed_when_stratified():
    # editor = direct editors; viewer = direct + parent viewers;
    # can_view = viewer - (viewer - editor) == viewer & editor, no cycle
    model = RelationModel([
        RelationSpec("document", "editor", This(), (direct_users(),)),
        RelationSpec(
            "document", "viewer", This(), (direct_users(),),
        ),
        RelationSpec(
            "document", "can_view",
            Difference(
                ComputedUserset("viewer"),
                Difference(ComputedUserset("viewer"), ComputedUserset("editor")),
            ),
            (),
        ),
    ])
    store = TupleStore(model=model)
    store.add("document:plan#viewer@user:alice")
    store.add("document:plan#viewer@user:bob")
    store.add("document:plan#editor@user:alice")
    checker = RelationChecker(model, store)
    assert checker.check("alice", "document:plan", "can_view")
    assert not checker.check("bob", "document:plan", "can_view")


def test_positive_cycle_through_difference_base_rejected():
    # x = (x union this) - y, y = this: x returns to x through a positive edge
    # nested under subtraction's base is fine, but if y points back to x via
    # subtraction it must be rejected.
    with pytest.raises(RelationModelError, match="negative recursion"):
        RelationModel([
            RelationSpec(
                "document", "x",
                Difference(Union(ComputedUserset("x"), This()), ComputedUserset("y")),
                (direct_users(),),
            ),
            RelationSpec(
                "document", "y",
                Difference(This(), ComputedUserset("x")),
                (direct_users(),),
            ),
        ])


def test_store_is_purely_in_memory(model, store, monkeypatch):
    # no socket/network path exists in the check path: block any connect attempt
    import socket

    def deny(*args, **kwargs):
        raise AssertionError("relation checks must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", lambda *a, **k: 1)
    store.add("document:plan#viewer@user:alice")
    enforcer = new_relation_enforcer(model, store)
    assert enforcer.enforce("alice", "document:plan", "view")
