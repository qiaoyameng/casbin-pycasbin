"""Wire relation tuple authorization into a normal Casbin enforcer.

The relation checker is exposed to the matcher as the custom function
``relation_check``, so a regular ``Enforcer.enforce(user, object, action)``
call is all callers need::

    e = new_relation_enforcer(model, store)
    e.enforce("user:alice", "document:plan.pdf", "view")

No policies and no external services are involved: only the caller's in-memory
tuples are consulted.
"""

from casbin import Enforcer
from casbin.model import Model

from .checker import RelationChecker
from .entities import entity, user
from .model import RelationModel

RELATION_MODEL_TEXT = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = relation_check(r.sub, r.obj, r.act)
"""

DEFAULT_ACTION_RELATIONS = {
    "view": "viewer",
    "edit": "editor",
    "owner": "owner",
}


def _relation_model():
    model = Model()
    model.load_model_from_text(RELATION_MODEL_TEXT)
    return model


class RelationEnforcer:
    """Casbin enforcer backed by relation tuples."""

    def __init__(self, model, store, action_relations=None):
        if not isinstance(model, RelationModel):
            raise TypeError("model must be a RelationModel")
        self.relation_model = model
        self.store = store
        self.checker = RelationChecker(model, store)
        self.action_relations = dict(DEFAULT_ACTION_RELATIONS)
        if action_relations:
            self.action_relations.update(action_relations)
        self.enforcer = Enforcer(_relation_model())
        self.enforcer.add_function("relation_check", self._relation_check)

    def enforce(self, sub, obj, act):
        """Normal authorization call: (subject, object, action) -> bool."""

        return self.enforcer.enforce(str(user(sub)), str(entity(obj)), act)

    def check_relation(self, sub, obj, relation):
        """Direct relation check, bypassing the action-to-relation mapping."""

        return self.checker.check(user(sub), entity(obj), relation)

    def add_tuple(self, value):
        return self.store.add(value)

    def remove_tuple(self, value):
        return self.store.remove(value)

    def _relation_check(self, sub, obj, act):
        relation = self.action_relations.get(act, act)
        ref = entity(obj)
        if self.relation_model.get(ref.type_name, relation) is None:
            return False
        return self.checker.check(user(sub), ref, relation)


def new_relation_enforcer(model, store, action_relations=None):
    """Build a Casbin enforcer evaluating relation tuples in its matcher."""

    return RelationEnforcer(model, store, action_relations)
