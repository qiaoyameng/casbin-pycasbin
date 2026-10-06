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

import copy
import logging
import re

from casbin.effect import Effector, get_effector, effect_to_bool
from casbin.model import Model, FunctionMap
from casbin.persist import Adapter
from casbin.persist.adapters import FileAdapter
from casbin.rbac import default_role_manager
from casbin.util import generate_g_function, SimpleEval, util, generate_conditional_g_function
from casbin.util.log import configure_logging, disabled_logging


class EnforceContext:
    """
    EnforceContext is used as the first element of the parameter "rvals" in method "enforce"
    """

    def __init__(self, rtype: str, ptype: str, etype: str, mtype: str):
        self.rtype: str = rtype
        self.ptype: str = ptype
        self.etype: str = etype
        self.mtype: str = mtype

    def get_cache_key(self):
        """lets CachedEnforcer key a request that carries an EnforceContext."""
        return self.rtype, self.ptype, self.etype, self.mtype


class PolicySnapshot:
    """An immutable, consistent view of the policy used by one enforce call.

    The model and the role managers in a snapshot are never mutated after
    publication: a batch commit builds a brand-new view and swaps it in. An
    enforce call captures the current snapshot on entry and keeps the same
    reference until it returns, so it always evaluates against either the whole
    old policy or the whole new one, including role relations.
    """

    __slots__ = ("version", "model", "rm_map", "cond_rm_map")

    def __init__(self, version, model, rm_map, cond_rm_map):
        self.version = version
        self.model = model
        self.rm_map = rm_map
        self.cond_rm_map = cond_rm_map


class CoreEnforcer:
    """CoreEnforcer defines the core functionality of an enforcer."""

    model_path = ""
    model = None
    fm = None
    eft = None

    adapter = None
    watcher = None
    rm_map = None
    cond_rm_map = None

    enabled = False
    auto_save = False
    auto_build_role_links = False
    auto_notify_watcher = False

    def __init__(self, model=None, adapter=None, enable_log=False, logging_config: dict = None):
        self.logger = logging.getLogger("casbin.enforcer")
        if isinstance(model, str):
            if isinstance(adapter, str):
                self.init_with_file(model, adapter)
            else:
                self.init_with_adapter(model, adapter)
                pass
        else:
            if isinstance(adapter, str):
                raise RuntimeError("Invalid parameters for enforcer.")
            else:
                self.init_with_model_and_adapter(model, adapter)

        if enable_log:
            configure_logging(logging_config)
        else:
            disabled_logging()

    def init_with_file(self, model_path, policy_path):
        """initializes an enforcer with a model file and a policy file."""
        a = FileAdapter(policy_path)
        self.init_with_adapter(model_path, a)

    def init_with_adapter(self, model_path, adapter=None):
        """initializes an enforcer with a database adapter."""
        m = self.new_model(model_path)
        self.init_with_model_and_adapter(m, adapter)

        self.model_path = model_path

    def init_with_model_and_adapter(self, m, adapter=None):
        """initializes an enforcer with a model and a database adapter."""

        if not isinstance(m, Model) or adapter is not None and not isinstance(adapter, Adapter):
            raise RuntimeError("Invalid parameters for enforcer.")

        self.adapter = adapter

        self.model = m
        self.model.print_model()
        self.fm = FunctionMap.load_function_map()

        self._initialize()

        # Do not initialize the full policy when using a filtered adapter
        if self.adapter and not self.is_filtered():
            self.load_policy()
        else:
            # no adapter: publish the empty/initial policy as the first view
            self.publish_snapshot(self.model, self.rm_map, self.cond_rm_map)

    def _initialize(self):
        self.rm_map = dict()
        self.cond_rm_map = dict()
        self.eft = get_effector(self.model["e"]["e"].value)
        self.watcher = None
        self._snapshot = None
        self._snapshot_version = 0

        self.enabled = True
        self.auto_save = True
        self.auto_build_role_links = True
        self.auto_notify_watcher = True

        self.init_rm_map()

    @staticmethod
    def new_model(path="", text=""):
        """creates a model."""

        m = Model()
        if len(path) > 0:
            m.load_model(path)
        else:
            m.load_model_from_text(text)

        return m

    def load_model(self):
        """reloads the model from the model CONF file.
        Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
        """

        self.model = self.new_model()
        self.model.load_model(self.model_path)
        self.model.print_model()
        self.fm = FunctionMap.load_function_map()

    def get_model(self):
        """gets the current model."""

        return self.model

    def set_model(self, m):
        """sets the current model."""

        self.model = m
        self.fm = FunctionMap.load_function_map()

    def get_adapter(self):
        """gets the current adapter."""

        return self.adapter

    def set_adapter(self, adapter):
        """sets the current adapter."""

        self.adapter = adapter

    def set_watcher(self, watcher):
        """sets the current watcher."""

        self.watcher = watcher
        pass

    def get_role_manager(self):
        """gets the current role manager."""
        return self.rm_map["g"]

    def get_named_role_manager(self, ptype):
        if ptype in self.rm_map.keys():
            return self.rm_map.get(ptype)
        raise ValueError("ptype not found")

    def set_role_manager(self, rm):
        """sets the current role manager."""
        self.rm_map["g"] = rm

    def set_named_role_manager(self, ptype, rm):
        self.rm_map[ptype] = rm

    def set_effector(self, eft):
        """sets the current effector."""
        self.eft = eft

    def clear_policy(self):
        """clears all policy."""

        self.model.clear_policy()

    def init_rm_map(self):
        if "g" in self.model.keys():
            for ptype in self.model["g"]:
                assertion = self.model["g"][ptype]
                if ptype in self.rm_map:
                    rm = self.rm_map[ptype]
                    rm.clear()
                    continue

                if len(assertion.tokens) <= 2 and len(assertion.params_tokens) == 0:
                    assertion.rm = default_role_manager.RoleManager(10)
                    self.rm_map[ptype] = assertion.rm

                if len(assertion.tokens) <= 2 and len(assertion.params_tokens) != 0:
                    assertion.cond_rm = default_role_manager.ConditionalRoleManager(10)
                    self.cond_rm_map[ptype] = assertion.cond_rm

                if len(assertion.tokens) > 2:
                    if len(assertion.params_tokens) == 0:
                        assertion.rm = default_role_manager.DomainManager(10)
                        self.rm_map[ptype] = assertion.rm
                    else:
                        assertion.cond_rm = default_role_manager.ConditionalDomainManager(10)
                        self.cond_rm_map[ptype] = assertion.cond_rm

    def load_policy(self):
        """reloads the policy from file/database."""
        new_model = copy.deepcopy(self.model)
        new_model.clear_policy()

        try:
            self.adapter.load_policy(new_model)

            new_model.sort_policies_by_subject_hierarchy()

            new_model.sort_policies_by_priority()

            new_model.print_policy()

            if self.auto_build_role_links:
                new_rm_map, new_cond_rm_map = self.clone_role_managers()
                for rm in new_rm_map.values():
                    rm.clear()
                if len(new_rm_map) != 0:
                    new_model.build_role_links(new_rm_map)

                for crm in new_cond_rm_map.values():
                    crm.clear()
                if len(new_cond_rm_map) != 0:
                    new_model.build_conditional_role_links(new_cond_rm_map)
            else:
                # role-link rebuilding is disabled: reuse the current managers so
                # links already present stay available, but publish them inside a
                # fresh snapshot bound to the new model
                new_rm_map, new_cond_rm_map = dict(self.rm_map), dict(self.cond_rm_map)
                self._bind_role_managers(new_model, new_rm_map, new_cond_rm_map)

            self.publish_snapshot(new_model, new_rm_map, new_cond_rm_map)

        except Exception as e:
            raise e

    def publish_snapshot(self, model, rm_map, cond_rm_map):
        """atomically publish a fully-built view.

        The model and role manager maps are replaced together. Old snapshots
        stay intact for enforce calls already in flight; the reference swap is
        atomic under the GIL and never serialises the whole enforce period.
        """
        self._snapshot_version += 1
        self.model = model
        self.rm_map = rm_map
        self.cond_rm_map = cond_rm_map
        self._snapshot = PolicySnapshot(self._snapshot_version, model, rm_map, cond_rm_map)

    def current_snapshot(self):
        """return the published view, publishing one from current state if none exists."""
        if self._snapshot is None:
            self.publish_snapshot(self.model, self.rm_map, self.cond_rm_map)
        return self._snapshot

    def clone_role_managers(self, model=None):
        """return fresh, independent role managers matching the current configuration.

        Role graphs contain cycles and live matching functions, so they are
        rebuilt as same-type instances rather than deep-copied.
        When *model* is given, its g assertions are rebound to the cloned managers
        (``build_role_links`` writes links through ``ast.rm``).
        """
        target_model = self.model if model is None else model
        rm_map = {}
        cond_rm_map = {}
        for ptype, rm in self.rm_map.items():
            clone = self._clone_one_role_manager(rm)
            rm_map[ptype] = clone
        for ptype, crm in self.cond_rm_map.items():
            cond_rm_map[ptype] = self._clone_one_role_manager(crm)
        self._bind_role_managers(target_model, rm_map, cond_rm_map)
        return rm_map, cond_rm_map

    @staticmethod
    def _bind_role_managers(model, rm_map, cond_rm_map):
        if "g" in model.keys():
            for ptype, ast in model["g"].items():
                if ptype in rm_map:
                    ast.rm = rm_map[ptype]
                if ptype in cond_rm_map:
                    ast.cond_rm = cond_rm_map[ptype]

    @staticmethod
    def _clone_one_role_manager(rm):
        max_level = getattr(rm, "max_hierarchy_level", 10)
        clone = rm.__class__(max_level)
        matching_func = getattr(rm, "matching_func", None)
        if matching_func is not None:
            clone.add_matching_func(matching_func)
        domain_matching_func = getattr(rm, "domain_matching_func", None)
        if domain_matching_func is not None:
            clone.add_domain_matching_func(domain_matching_func)
        return clone


    def load_filtered_policy(self, filter):
        """reloads a filtered policy from file/database."""
        self.model.clear_policy()

        if not hasattr(self.adapter, "is_filtered"):
            raise ValueError("filtered policies are not supported by this adapter")

        self.adapter.load_filtered_policy(self.model, filter)

        self.model.sort_policies_by_priority()

        self.init_rm_map()
        self.model.print_policy()
        if self.auto_build_role_links:
            self.build_role_links()
        self.publish_snapshot(self.model, self.rm_map, self.cond_rm_map)

    def load_increment_filtered_policy(self, filter):
        """LoadIncrementalFilteredPolicy append a filtered policy from file/database."""
        if not hasattr(self.adapter, "is_filtered"):
            raise ValueError("filtered policies are not supported by this adapter")

        self.adapter.load_filtered_policy(self.model, filter)
        self.model.print_policy()
        if self.auto_build_role_links:
            self.build_role_links()
        self.publish_snapshot(self.model, self.rm_map, self.cond_rm_map)

    def is_filtered(self):
        """returns true if the loaded policy has been filtered."""

        return hasattr(self.adapter, "is_filtered") and self.adapter.is_filtered()

    def save_policy(self):
        if self.is_filtered():
            raise RuntimeError("cannot save a filtered policy")

        self.adapter.save_policy(self.model)

        if self.watcher:
            if callable(getattr(self.watcher, "update_for_save_policy", None)):
                self.watcher.update_for_save_policy(self.model)
            else:
                self.watcher.update()

    def enable_enforce(self, enabled=True):
        """changes the enforcing state of Casbin,
        when Casbin is disabled, all access will be allowed by the Enforce() function.
        """

        self.enabled = enabled

    def enable_auto_save(self, auto_save):
        """controls whether to save a policy rule automatically to the adapter when it is added or removed."""
        self.auto_save = auto_save

    def enable_auto_build_role_links(self, auto_build_role_links):
        """controls whether to rebuild the role inheritance relations when a role is added or deleted."""
        self.auto_build_role_links = auto_build_role_links

    def enable_auto_notify_watcher(self, auto_notify_watcher):
        """controls whether to save a policy rule automatically notify the watcher when it is added or removed."""
        self.auto_notify_watcher = auto_notify_watcher

    def build_role_links(self):
        """manually rebuild the role inheritance relations."""

        for rm in self.rm_map.values():
            rm.clear()

        self.model.build_role_links(self.rm_map)

    def add_named_matching_func(self, ptype, fn):
        """add_named_matching_func add MatchingFunc by ptype RoleManager"""
        try:
            self.rm_map[ptype].add_matching_func(fn)
            return True
        except:
            return False

    def add_named_domain_matching_func(self, ptype, fn):
        """add_named_domain_matching_func add MatchingFunc by ptype to RoleManager"""
        if ptype in self.rm_map.keys():
            self.rm_map[ptype].add_domain_matching_func(fn)
            return True

        return False

    def add_named_link_condition_func(self, ptype, user, role, fn):
        """Add condition function fn for Link userName->roleName,
        when fn returns true, Link is valid, otherwise invalid"""
        if ptype in self.cond_rm_map:
            rm = self.cond_rm_map[ptype]
            rm.add_link_condition_func(user, role, fn)
            return True
        return False

    def add_named_domain_link_condition_func(self, ptype, user, role, domain, fn):
        """Add condition function fn for Link userName-> {roleName, domain},
        when fn returns true, Link is valid, otherwise invalid"""
        if ptype in self.cond_rm_map:
            rm = self.cond_rm_map[ptype]
            rm.add_domain_link_condition_func(user, role, domain, fn)
            return True
        return False

    def set_named_link_condition_func_params(self, ptype, user, role, *params):
        """Sets the parameters of the condition function fn for Link userName->roleName"""
        if ptype in self.cond_rm_map:
            rm = self.cond_rm_map[ptype]
            rm.set_link_condition_func_params(user, role, *params)
            return True
        return False

    def set_named_domain_link_condition_func_params(self, ptype, user, role, domain, *params):
        """Sets the parameters of the condition function fn for Link userName->{roleName, domain}"""
        if ptype in self.cond_rm_map:
            rm = self.cond_rm_map[ptype]
            rm.set_domain_link_condition_func_params(user, role, domain, *params)
            return True
        return False

    def new_enforce_context(self, suffix: str) -> EnforceContext:
        return EnforceContext(
            rtype="r" + suffix,
            ptype="p" + suffix,
            etype="e" + suffix,
            mtype="m" + suffix,
        )

    def enforce(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        """
        result, _ = self.enforce_ex(*rvals)
        return result

    def enforce_ex(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        return judge result with reason
        """
        # Capture one complete view on entry. The whole request runs against this
        # snapshot (rules and role links together); a concurrent batch commit
        # publishes a different snapshot and cannot make this request see a mix.
        snapshot = self.current_snapshot()
        view_model = snapshot.model

        rtype = "r"
        ptype = "p"
        etype = "e"
        mtype = "m"

        if not self.enabled:
            return [True, []]

        # Copy the function table: it is shared mutable state, and a later
        # enforce call rebuilds the g() closures against its own snapshot. Without
        # the copy that rebuild would overwrite the g this request is mid-way
        # through using, re-mixing new role links into an old view.
        functions = dict(self.fm.get_functions())

        if "g" in view_model.keys():
            for key, ast in view_model["g"].items():
                if len(snapshot.rm_map) != 0:
                    functions[key] = generate_g_function(snapshot.rm_map[key])
                if len(snapshot.cond_rm_map) != 0:
                    functions[key] = generate_conditional_g_function(ast.cond_rm)

        if len(rvals) != 0:
            if isinstance(rvals[0], EnforceContext):
                enforce_context = rvals[0]
                rtype = enforce_context.rtype
                ptype = enforce_context.ptype
                etype = enforce_context.etype
                mtype = enforce_context.mtype
                rvals = rvals[1:]

        if "m" not in view_model.keys():
            raise RuntimeError("model is undefined")

        if "m" not in view_model["m"].keys():
            raise RuntimeError("model is undefined")

        r_tokens = view_model["r"][rtype].tokens
        p_tokens = view_model["p"][ptype].tokens

        if len(r_tokens) != len(rvals):
            raise RuntimeError("invalid request size")

        exp_string = view_model["m"][mtype].value
        exp_has_eval = util.has_eval(exp_string)
        if not exp_has_eval:
            expression = self._get_expression(exp_string, functions)

        policy_effects = set()

        r_parameters = dict(zip(r_tokens, rvals))

        policy = view_model["p"][ptype].policy
        policy_len = len(policy)

        explain_index = -1
        if not 0 == policy_len:
            for i, pvals in enumerate(policy):
                if len(p_tokens) != len(pvals):
                    raise RuntimeError("invalid policy size")

                p_parameters = dict(zip(p_tokens, pvals))
                parameters = dict(r_parameters, **p_parameters)

                if exp_has_eval:
                    rule_names = util.get_eval_value(exp_string)
                    rules = [util.escape_assertion(p_parameters[rule_name]) for rule_name in rule_names]
                    exp_with_rule = util.replace_eval(exp_string, rules)
                    expression = self._get_expression(exp_with_rule, functions)

                result = expression.eval(parameters)

                if isinstance(result, bool):
                    if not result:
                        policy_effects.add(Effector.INDETERMINATE)
                        continue
                elif isinstance(result, float):
                    if 0 == result:
                        policy_effects.add(Effector.INDETERMINATE)
                        continue
                else:
                    raise RuntimeError("matcher result should be bool, int or float")

                p_eft_key = ptype + "_eft"
                if p_eft_key in parameters.keys():
                    eft = parameters[p_eft_key]
                    if "allow" == eft:
                        policy_effects.add(Effector.ALLOW)
                    elif "deny" == eft:
                        policy_effects.add(Effector.DENY)
                    else:
                        policy_effects.add(Effector.INDETERMINATE)
                else:
                    policy_effects.add(Effector.ALLOW)

                # Update explain_index for any matching policy before checking early break condition
                # to ensure explanations are captured for allow rules in deny models
                explain_index = i

                if self.eft.intermediate_effect(policy_effects) != Effector.INDETERMINATE:
                    break

        else:
            if exp_has_eval:
                raise RuntimeError("please make sure rule exists in policy when using eval() in matcher")

            parameters = r_parameters.copy()

            for token in view_model["p"][ptype].tokens:
                parameters[token] = ""

            result = expression.eval(parameters)

            if result:
                policy_effects.add(Effector.ALLOW)
            else:
                policy_effects.add(Effector.INDETERMINATE)

        final_effect = self.eft.final_effect(policy_effects)
        result = effect_to_bool(final_effect)

        # Log request.
        if (result and self.logger.isEnabledFor(logging.INFO)) or (
            not result and self.logger.isEnabledFor(logging.WARNING)
        ):
            req_str = "Request: "
            req_str = req_str + ", ".join([str(v) for v in rvals])
            req_str = req_str + " ---> %s" % result
            if result:
                self.logger.info(req_str)
            else:
                # leaving this in warning for now, if it's very noise this can be changed to info or debug,
                # or change the log level
                self.logger.warning(req_str)

        explain_rule = []
        if explain_index != -1 and explain_index < policy_len:
            explain_rule = policy[explain_index]

        return result, explain_rule

    def batch_enforce(self, rvals):
        """batch_enforce enforce in batches"""
        results = []
        for request in rvals:
            result = self.enforce(*request)
            results.append(result)
        return results

    @staticmethod
    def configure_logging(logging_config=None):
        """configure_logging configure the default logger for casbin"""
        configure_logging(logging_config)

    @staticmethod
    def _get_expression(expr, functions=None):
        expr = expr.replace("&&", "and")
        expr = expr.replace("||", "or")
        expr = re.sub(r"!(?!=)", "not ", expr)

        return SimpleEval(expr, functions)
