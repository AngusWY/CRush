
import json
import math
import os, sys
from collections import deque

import lian.config.config as config
import networkx as nx

from lian.events.default_event_handlers.this_field_write import access_path_formatter
from lian.util import util
from lian.util.readable_gir import get_gir_str
from lian.taint.rule_manager import RuleManager, Rule
from lian.core.sfg_dumper import SFGDumper
from lian.config.constants import (
    ANALYSIS_PHASE_ID,
    SFG_NODE_KIND,
    SFG_EDGE_KIND,
    TAG_KEYWORD
)
from lian.taint.taint_structs import (
    TaintEnv,
    Flow,
)
from pyarrow.lib import ArrowInvalid
import traceback

class PathFinder:


    def __init__(self, taint_analysis):
        self.ta = taint_analysis

    @property
    def sfg(self):
        return self.ta.sfg

    @property
    def taint_manager(self):
        return self.ta.taint_manager

    @property
    def rule_applier(self):
        return self.ta.rule_applier

    def _get_node_tag(self, u):

        if u.node_type == SFG_NODE_KIND.SYMBOL:
            return self.taint_manager.get_symbol_tag(u.node_id)
        elif u.node_type == SFG_NODE_KIND.STATE:
            return self.taint_manager.get_state_tag(u.node_id)
        elif u.node_type == SFG_NODE_KIND.STMT:
            u_tag = 0
            for pred in self.sfg.predecessors(u):
                edge_data = self.sfg.get_edge_data(pred, u)
                if edge_data:
                    for data in edge_data.values():
                        if data.edge_type == SFG_EDGE_KIND.SYMBOL_IS_USED:
                            u_tag |= self.taint_manager.get_symbol_tag(pred.node_id)
            return u_tag
        return 0

    def _enqueue(self, worklist, in_worklist, node):

        if node in in_worklist:
            return
        worklist.append(node)
        in_worklist.add(node)

    def _init_source_contamination(self, source, tag, worklist, in_worklist):

        if source.node_type == SFG_NODE_KIND.SYMBOL:
            self.taint_manager.set_symbol_tag(source.node_id, tag)
            self._enqueue(worklist, in_worklist, source)

            for v in self.sfg.successors(source):
                edge_data = self.sfg.get_edge_data(source, v)
                if edge_data:
                    for data in edge_data.values():
                        if data.edge_type == SFG_EDGE_KIND.SYMBOL_STATE:
                            self.taint_manager.set_states_tag([v.node_id], tag)
                            self._enqueue(worklist, in_worklist, v)
        elif source.node_type == SFG_NODE_KIND.STATE:
            self.taint_manager.set_states_tag([source.node_id], tag)
            self._enqueue(worklist, in_worklist, source)
        elif source.node_type == SFG_NODE_KIND.STMT:
            self._enqueue(worklist, in_worklist, source)

    def _node_family(self, node):

        node_id = getattr(node, "node_id", None)
        if node_id is None:
            return [node]
        family = self._node_id_index.get(node_id)
        return family if family else [node]

    def _propagate_from_symbol(self, u, u_tag, worklist, in_worklist):

        for instance in self._node_family(u):
            for v in self.sfg.successors(instance):
                edge_data = self.sfg.get_edge_data(instance, v)
                if edge_data:
                    for data in edge_data.values():
                        etype = data.edge_type

                        if etype == SFG_EDGE_KIND.SYMBOL_STATE:
                            v_tag = self.taint_manager.get_state_tag(v.node_id)
                            if (u_tag | v_tag) != v_tag:
                                self.taint_manager.set_states_tag([v.node_id], u_tag | v_tag)
                                self._enqueue(worklist, in_worklist, v)
                        elif etype == SFG_EDGE_KIND.SYMBOL_IS_USED:

                            self._enqueue(worklist, in_worklist, v)
                        elif etype in (SFG_EDGE_KIND.SYMBOL_FLOW, SFG_EDGE_KIND.INDIRECT_SYMBOL_FLOW):

                            if v.node_type != SFG_NODE_KIND.SYMBOL:
                                continue
                            v_tag = self.taint_manager.get_symbol_tag(v.node_id)
                            if (u_tag | v_tag) != v_tag:
                                self.taint_manager.set_symbol_tag(v.node_id, u_tag | v_tag)
                                self._enqueue(worklist, in_worklist, v)

    def _propagate_from_state(self, u, u_tag, worklist, in_worklist):




        for instance in [u]:
            for v in self.sfg.predecessors(instance):
                edge_data = self.sfg.get_edge_data(v, instance)
                if edge_data:
                    for data in edge_data.values():
                        if data.edge_type in (SFG_EDGE_KIND.SYMBOL_STATE, SFG_EDGE_KIND.STATE_INCLUSION):
                            v_tag = self.taint_manager.get_symbol_tag(v.node_id)
                            if (u_tag | v_tag) != v_tag:
                                self.taint_manager.set_symbol_tag(v.node_id, u_tag | v_tag)
                                self._enqueue(worklist, in_worklist, v)


        for instance in self._node_family(u):
            for v in self.sfg.successors(instance):
                if v.node_type == SFG_NODE_KIND.STATE:
                    edge_data = self.sfg.get_edge_data(instance, v)
                    if edge_data:
                        for data in edge_data.values():
                            if data.edge_type in (SFG_EDGE_KIND.STATE_INCLUSION,
                                                                SFG_EDGE_KIND.INDIRECT_STATE_INCLUSION):
                                v_tag = self.taint_manager.get_state_tag(v.node_id)
                                if (u_tag | v_tag) != v_tag:
                                    self.taint_manager.set_states_tag([v.node_id], u_tag | v_tag)
                                    self._enqueue(worklist, in_worklist, v)

    def _propagate_from_stmt(self, u, u_tag, worklist, in_worklist):


        if self.rule_applier.apply_propagation_rules(u):
            for v in self.sfg.successors(u):
                edge_data = self.sfg.get_edge_data(u, v)
                if edge_data:
                    for data in edge_data.values():

                        if data.edge_type == SFG_EDGE_KIND.SYMBOL_IS_DEFINED:
                            v_tag = self.taint_manager.get_symbol_tag(v.node_id)
                            if (u_tag | v_tag) != v_tag:
                                self.taint_manager.set_symbol_tag(v.node_id, u_tag | v_tag)

                                self._enqueue(worklist, in_worklist, v)
                            else:


                                if getattr(self, "_processed_nodes", None) is not None and v not in self._processed_nodes:
                                    self._enqueue(worklist, in_worklist, v)



            if getattr(u, "name", None) == "object_call_stmt":
                for pred in self.sfg.predecessors(u):
                    edge_data = self.sfg.get_edge_data(pred, u)
                    if not edge_data:
                        continue
                    for data in edge_data.values():
                        weight = data
                        if not weight:
                            continue
                        if weight.edge_type != SFG_EDGE_KIND.SYMBOL_IS_USED:
                            continue

                        if getattr(weight, "pos", -1) != 0:
                            continue
                        if pred.node_type != SFG_NODE_KIND.SYMBOL:
                            continue
                        pred_tag = self.taint_manager.get_symbol_tag(pred.node_id)
                        if (u_tag | pred_tag) != pred_tag:
                            self.taint_manager.set_symbol_tag(pred.node_id, u_tag | pred_tag)
                            self._enqueue(worklist, in_worklist, pred)
                        else:
                            if getattr(self, "_processed_nodes", None) is not None and pred not in self._processed_nodes:
                                self._enqueue(worklist, in_worklist, pred)

                        break


    def propagate_taint(self, source):

        tag_info = Rule(name=f"Source_{source.def_stmt_id}", operation="source_propagation", rule_id=id(source))
        tag = self.taint_manager.add_and_update_tag_bv(tag_info, 0)

        worklist = deque()
        in_worklist = set()


        self._processed_nodes = set()



        self._node_id_index = {}
        for node in self.sfg.nodes():
            node_id = getattr(node, "node_id", None)
            if node_id is None:
                continue
            self._node_id_index.setdefault(node_id, []).append(node)
        self._init_source_contamination(source, tag, worklist, in_worklist)


        while worklist:
            u = worklist.popleft()
            in_worklist.discard(u)
            self._processed_nodes.add(u)

            try:
                self.taint_manager.mark_processed_node(u)
            except Exception:
                pass
            u_tag = self._get_node_tag(u)

            if u_tag == 0:
                continue

            if u.node_type == SFG_NODE_KIND.SYMBOL:
                self._propagate_from_symbol(u, u_tag, worklist, in_worklist)
            elif u.node_type == SFG_NODE_KIND.STATE:
                self._propagate_from_state(u, u_tag, worklist, in_worklist)
            elif u.node_type == SFG_NODE_KIND.STMT:
                self._propagate_from_stmt(u, u_tag, worklist, in_worklist)

        self._processed_nodes = set()
        return tag

    def reconstruct_define_use_path(self, source, sink):

        visited = set()
        longest_path = []

        def dfs(u, path_stmts):
            nonlocal longest_path
            if u in visited:
                return None
            visited.add(u)


            new_path = list(path_stmts)
            if u.node_type == SFG_NODE_KIND.STMT:
                if not new_path or new_path[-1] != u:
                    new_path.append(u)


            if len(new_path) >= len(longest_path):
                longest_path = new_path


            if u == sink:
                return new_path


            for v in self.sfg.successors(u):
                result = dfs(v, new_path)
                if result:
                    return result

            return None

        final_path = dfs(source, [])

        if final_path is None:

            if not longest_path or longest_path[-1] != sink:
                final_path = longest_path + [sink]
            else:
                final_path = longest_path

        flow = Flow()
        flow.source_stmt_id = source.def_stmt_id
        flow.sink_stmt_id = sink.def_stmt_id
        flow.parent_to_sink = final_path
        return flow


class TaintRuleApplier:
    def __init__(self, taint_analysis):
        self.taint_analysis = taint_analysis
        self.loader = taint_analysis.loader
        self.sfg = taint_analysis.sfg
        self.rule_manager = taint_analysis.rule_manager

    def apply_parameter_source_rules(self, node):
        stmt_id = node.def_stmt_id
        method_id = self.loader.convert_stmt_id_to_method_id(stmt_id)
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        stmt = node.stmt





        parameter_symbol = list(util.graph_successors(self.sfg, node))[0]
        for rule in self.rule_manager.all_sources:


            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(stmt.start_row + 1):
                continue
            if not rule.attr and rule.name == parameter_symbol.name:
                return True
            if rule.operation != "parameter_decl":
                continue


            if rule.name == parameter_symbol.name:
                return True
        return False

    def apply_field_read_source_rules(self, node):

        symbol_node, state_nodes = self.taint_analysis.get_stmt_define_symbol_and_states_node(node)
        if not symbol_node or not state_nodes:
            return False

        for rule in self.rule_manager.all_sources:
            if rule.operation != "field_read":
                continue

            for state_node in state_nodes:

                access_path = access_path_formatter(state_node.access_path)
                if access_path in [rule.name, rule.target]:
                    return True

        return False

    def apply_call_stmt_source_rules(self, node):
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node, pos=0)
        defined_symbol_node, defined_state_nodes = self.taint_analysis.get_stmt_define_symbol_and_states_node(node)
        if not method_symbol_node or not defined_symbol_node:
            return False

        tag_space_id = defined_symbol_node.node_id
        apply_rule_flag = False
        for rule in self.rule_manager.all_sources:
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.operation != "call_stmt":
                continue
            tag_info = rule
            name = tag_info.name
            for state_node in method_state_nodes:
                state_access_path = state_node.access_path
                if isinstance(state_access_path, str):
                    continue
                access_path = access_path_formatter(state_access_path)

                if len(access_path) == 0:
                    access_path = method_symbol_node.name
                if access_path == name:
                    apply_rule_flag = True
                    tag = self.taint_analysis.taint_manager.get_symbol_tag(tag_space_id)
                    new_tag = self.taint_analysis.taint_manager.add_and_update_tag_bv(tag_info=tag_info,
                                                                                      current_taint=tag)
                    self.taint_analysis.taint_manager.set_symbols_tag([tag_space_id], new_tag)
                    for defined_state_node in defined_state_nodes:
                        self.taint_analysis.taint_manager.set_states_tag([defined_state_node.node_id], new_tag)

        return apply_rule_flag

    def apply_object_call_stmt_source_rules(self, node):
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "object_call_stmt":
            return False
        stmt = node.stmt
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node, pos = 0)
        names = []
        if method_state_nodes and len(method_state_nodes) > 0:
            for state in method_state_nodes:
                if util.is_available(stmt.field):
                    names.append(util.access_path_formatter(state.access_path) + '.' + str(stmt.field))
        if util.is_available(stmt.receiver_object) and util.is_available(stmt.field):
            names.append(str(stmt.receiver_object) + '.' + str(stmt.field))
        for rule in self.rule_manager.all_sources:
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.name in names:
                return True
        return False

    def should_apply_object_call_stmt_sink_rules(self, node):
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "object_call_stmt":
            return False
        stmt = node.stmt
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
        names = []
        if method_state_nodes and len(method_state_nodes) > 0:
            for state in method_state_nodes:
                if util.is_available(stmt.field):
                    names.append(util.access_path_formatter(state.access_path) + '.' + str(stmt.field))

        if util.is_available(stmt.receiver_object) and util.is_available(stmt.field):
            names.append(str(stmt.receiver_object) + '.' + str(stmt.field))
        if stmt.field == "__init__":
            names.append("__init__")
        for rule in self.rule_manager.all_sinks:
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.name in names:
                return True
        return False

    def should_apply_new_object_sink_rules(self, node):
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "new_object":
            return False
        stmt = node.stmt
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        data_type = util.read_stmt_field(stmt.data_type)

        for rule in self.rule_manager.all_sinks:
            if rule.operation != "new_object":
                continue
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.name == data_type:
                return True
        return False

    def should_apply_call_stmt_sink_rules(self, node):
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "call_stmt":
            return False
        method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node, pos=0)
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        for rule in self.rule_manager.all_sinks:
            if rule.operation != "call_stmt":
                continue


            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if not method_state_nodes:
                continue
            for state_node in method_state_nodes:

                if self.check_method_name(rule.name, state_node):
                    return True

        return False
    def apply_rules_from_code(self, node, rules):
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path

        for rule in rules:
            if rule.unit_path not in unit_path:
                continue
            if node.line_no + 1 != rule.line_num:
                continue
            if rule.symbol_name in node.operation:
                return True
        return False

    def apply_record_write_sink_rules(self, node):
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "record_write":
            return False

        for rule in self.rule_manager.all_sinks:
            if rule.operation != "record_write":
                continue
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.key and rule.key == node.stmt.key:
                return True

        return False

    def apply_field_write_sink_rules(self, node):
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "field_write":
            return False

        for rule in self.rule_manager.all_sinks:
            if rule.operation != "field_write":
                continue
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.name and rule.name in node.operation:
                return True

        return False

    def check_method_name(self, rule_name, method_state):
        state_access_path = method_state.access_path
        rule_name_parts = rule_name.split('.')
        if len(state_access_path) < len(rule_name_parts):
            return False

        for i, item in enumerate(reversed(rule_name_parts)):
            if item == TAG_KEYWORD.ANYNAME:
                continue
            if item != state_access_path[-i - 1].key:
                return False
        return True

    def apply_propagation_rules(self, node):
        stmt_id = node.def_stmt_id
        stmt = node.stmt
        operation = node.name


        if operation in ["assign_stmt", "call_stmt", "object_call_stmt", "new_object", "forin_stmt", "field_read","field_write", "record_write","record_extend", "array_write", "array_extend", "array_append", "array_read"] :
            return True

        for rule in self.rule_manager.all_propagations:
            if rule.operation != operation:
                continue

            if operation == "field_read":

                if hasattr(stmt, 'field') and rule.field:
                    if stmt.field in rule.field:
                        return True

                symbol_node, state_nodes = self.taint_analysis.get_stmt_define_symbol_and_states_node(node)
                if state_nodes:
                    for state_node in state_nodes:
                        access_path = access_path_formatter(state_node.access_path)
                        if access_path == rule.target:
                            return True

                if not rule.field and not rule.target:
                    return True

            elif operation == "call_stmt":

                method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
                if method_state_nodes:
                    for state_node in method_state_nodes:
                        if self.check_method_name(rule.name, state_node):
                            return True

                if not rule.name:
                    return True

        return False

    def get_sink_tag_by_rules(self, node):
        sink_tag = 0
        vuln_type = None
        if node.node_type != SFG_NODE_KIND.STMT:
            return sink_tag,  vuln_type

        stmt_id = node.def_stmt_id
        stmt = node.stmt
        operation = node.name


        matching_rules = []
        if operation == "call_stmt":
            _, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node, pos=0)
            for rule in self.rule_manager.all_sinks:
                if rule.operation != "call_stmt":
                    continue
                if not method_state_nodes:
                    if rule.name == stmt.name:
                        matching_rules.append(rule)
                    continue
                for state_node in method_state_nodes:
                    if self.check_method_name(rule.name, state_node):
                        matching_rules.append(rule)
                        break
        elif operation == "object_call_stmt":
            method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
            name = None
            if method_state_nodes and len(method_state_nodes) > 0 and util.is_available(stmt.field):
                name = util.access_path_formatter(method_state_nodes[0].access_path) + '.' + str(stmt.field)

            name1 = None
            if util.is_available(stmt.receiver_object) and util.is_available(stmt.field):
                name1 = str(stmt.receiver_object) + '.' + str(stmt.field)
            for rule in self.rule_manager.all_sinks:
                if rule.name in [name, name1, stmt.field]:
                    matching_rules.append(rule)
        elif operation == "new_object":
            data_type = util.read_stmt_field(stmt.data_type)
            for rule in self.rule_manager.all_sinks:
                if rule.operation != "new_object":
                    continue
                if rule.name == data_type:
                    matching_rules.append(rule)
        elif operation == "field_write":
            used_symbol_nodes, used_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
            for rule in self.rule_manager.all_sinks:
                if rule.operation != "field_write":
                    continue
                if rule.name in node.operation:
                    matching_rules.append(rule)
        elif operation == "field_write":
            used_symbol_nodes, used_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
            for rule in self.rule_manager.all_sinks:
                if rule.operation != "field_write":
                    continue
                if rule.name in node.operation:
                    matching_rules.append(rule)


        for rule in matching_rules:
            targets = rule.target if isinstance(rule.target, list) else [rule.target]
            vuln_type = rule.vuln_type
            for target in targets:
                if isinstance(target, str):
                    target = target.strip()
                target_pos = -1
                if target == TAG_KEYWORD.ARG0:
                    target_pos = 1
                elif target == TAG_KEYWORD.ARG1:
                    target_pos = 2
                elif target == TAG_KEYWORD.ARG2:
                    target_pos = 3
                elif target == TAG_KEYWORD.ARG3:
                    target_pos = 4
                elif target == TAG_KEYWORD.ARG4:
                    target_pos = 5
                elif target in [TAG_KEYWORD.RECEIVER, TAG_KEYWORD.TARGET]:
                    target_pos = 0

                for pred in self.sfg.predecessors(node):
                    edge_data = self.sfg.get_edge_data(pred, node)
                    if not edge_data: continue
                    for data in edge_data.values():
                        weight = data
                        if weight.edge_type != SFG_EDGE_KIND.SYMBOL_IS_USED:
                            continue

                        weight_pos = weight.pos
                        if operation == "object_call_stmt" and target_pos != 0:
                            weight_pos -= 1


                        if (target_pos != -1 and weight_pos == target_pos) or \
                            (target == TAG_KEYWORD.TARGET) or \
                            (not target):
                            sink_tag |= self.taint_analysis.get_symbol_with_states_tag(pred)

        is_sink_node = False
        for rule in self.rule_manager.all_sinks_from_code:
            if node.line_no + 1 != rule.line_num:
                continue
            if rule.symbol_name in node.operation:
                is_sink_node = True
        if is_sink_node:
            for pred in self.sfg.predecessors(node):
                sink_tag |= self.taint_analysis.get_symbol_with_states_tag(pred)
        return sink_tag, vuln_type


class TaintAnalysis:
    def __init__(self, lian, options):
        self.lian = lian
        self.loader = self.lian.loader
        self.options = options
        self.default_settings = options.default_settings
        self.taint_manager: TaintEnv = None
        self.rule_manager = RuleManager(options.default_settings)
        self.current_entry_point = -1
        self.sfg = None
        self.rule_applier = TaintRuleApplier(self)
        self.path_finder = PathFinder(self)

    def _update_sfg(self, sfg):
        self.sfg = sfg
        self.rule_applier.sfg = sfg
        self.path_finder.ta = self

    def read_rules(self, operation, source_rules):

        rules = []

        for rule in source_rules:
            if rule.operation == operation:
                rules.append(rule)
        return rules

    def get_stmt_used_symbol_and_state_by_pos(self, node, pos = -1):
        if node.node_type != SFG_NODE_KIND.STMT:
            return None, None
        state_nodes = []
        predecessors = list(util.graph_predecessors(self.sfg, node))
        name_symbol_node = None
        if len(predecessors) == 0:
            return None, None
        for predecessor in predecessors:
            edge = self.sfg.get_edge_data(predecessor, node)

            if edge and edge['weight'].pos == pos:
                name_symbol_node = predecessor
        name_symbol_successors = list(util.graph_successors(self.sfg, name_symbol_node))
        for successor in name_symbol_successors:
            if successor.node_type == SFG_NODE_KIND.STATE:
                state_nodes.append(successor)
        return name_symbol_node, state_nodes

    def get_stmt_define_symbol_and_states_node(self, node):
        if node.node_type != SFG_NODE_KIND.STMT:
            return None, None
        successors = list(util.graph_successors(self.sfg, node))
        define_symbol_node = None
        for successor in successors:
            if successor.node_id == -1 or successor.name == "":
                continue
            edge = self.sfg.get_edge_data(node, successor)
            if edge and edge['weight'].edge_type == SFG_EDGE_KIND.SYMBOL_IS_DEFINED:
                define_symbol_node = successor
        define_symbol_successors = list(util.graph_successors(self.sfg, define_symbol_node))
        define_state_list = []
        for successor in define_symbol_successors:
            edge = self.sfg.get_edge_data(define_symbol_node, successor)
            if edge and edge['weight'].edge_type == SFG_EDGE_KIND.SYMBOL_STATE:
                define_state_list.append(successor)
        return define_symbol_node, define_state_list

    def find_sources(self):
        node_list = []



        for node in self.sfg.nodes:
            if node.node_type != SFG_NODE_KIND.STMT:
                continue
            if node.name == "call_stmt" and self.rule_applier.apply_call_stmt_source_rules(node):
                defined_symbol_node, defined_state_nodes = self.get_stmt_define_symbol_and_states_node(node)
                if defined_symbol_node is not None:
                    node_list.append(defined_symbol_node)
            elif node.name == "object_call_stmt" and self.rule_applier.apply_object_call_stmt_source_rules(node):
                defined_symbol_node, defined_state_nodes = self.get_stmt_define_symbol_and_states_node(node)
                if defined_symbol_node is not None:
                    node_list.append(defined_symbol_node)
            elif node.name == "parameter_decl" and self.rule_applier.apply_parameter_source_rules(node):
                defined_symbol_node, defined_state_nodes = self.get_stmt_define_symbol_and_states_node(node)
                if defined_symbol_node is not None:
                    node_list.append(defined_symbol_node)
            elif node.name == "field_read" and self.rule_applier.apply_field_read_source_rules(node):
                defined_symbol_node, defined_state_nodes = self.get_stmt_define_symbol_and_states_node(node)
                if defined_symbol_node is not None:
                    node_list.append(defined_symbol_node)

            else:
                rules = self.rule_manager.all_sources_from_code
                if self.rule_applier.apply_rules_from_code(node, rules):
                    defined_symbol_node, defined_state_nodes = self.get_stmt_define_symbol_and_states_node(node)
                    if defined_symbol_node is not None:
                        node_list.append(defined_symbol_node)

        return node_list

    def access_path_formatter(self, state_access_path):
        key_list = []
        for item in state_access_path:
            key = item.key
            key = key if isinstance(key, str) else str(key)
            if key != "":
                key_list.append(key)


        access_path = '.'.join(key_list)
        return access_path

    def find_sinks(self):


        node_list = []
        for node in self.sfg.nodes:
            if self.rule_applier.should_apply_call_stmt_sink_rules(
                node) or self.rule_applier.should_apply_object_call_stmt_sink_rules(node):
                node_list.append(node)
            elif self.rule_applier.should_apply_new_object_sink_rules(node):
                node_list.append(node)
            elif self.rule_applier.apply_record_write_sink_rules(node):
                node_list.append(node)
            elif self.rule_applier.apply_field_write_sink_rules(node):
                node_list.append(node)
            else:
                rules = self.rule_manager.all_sinks_from_code
                if self.rule_applier.apply_rules_from_code(node, rules):
                    node_list.append(node)
        return node_list

    def check_method_name(self, rule_name, method_state):
        apply_flag = True

        state_access_path = method_state.access_path

        rule_name = rule_name.split('.')
        if len(state_access_path) < len(rule_name):
            return False

        for i, item in enumerate(reversed(rule_name)):
            if item == TAG_KEYWORD.ANYNAME:
                continue
            if item != state_access_path[-i - 1].key:
                apply_flag = False
                break

        return apply_flag

    def get_state_with_inclusion_tag(self, state_node):

        tag = 0
        state_worklist = deque([state_node])
        state_visited = {state_node}
        while state_worklist:
            curr_state = state_worklist.popleft()
            tag |= self.taint_manager.get_state_tag(curr_state.node_id)

            for next_state in self.sfg.successors(curr_state):
                if next_state.node_type == SFG_NODE_KIND.STATE and next_state not in state_visited:
                    s_edge_data = self.sfg.get_edge_data(curr_state, next_state)
                    if s_edge_data:
                        for s_data in s_edge_data.values():
                            if s_data.edge_type in (
                                    SFG_EDGE_KIND.STATE_INCLUSION,
                                    SFG_EDGE_KIND.INDIRECT_STATE_INCLUSION):
                                state_visited.add(next_state)
                                state_worklist.append(next_state)
                                break
        return tag

    def get_symbol_with_states_tag(self, symbol_node):

        tag = self.taint_manager.get_symbol_tag(symbol_node.node_id)
        for v in self.sfg.successors(symbol_node):
            v_edge_data = self.sfg.get_edge_data(symbol_node, v)
            if v_edge_data:
                for v_data in v_edge_data.values():
                    if v_data.edge_type == SFG_EDGE_KIND.SYMBOL_STATE:
                        tag |= self.get_state_with_inclusion_tag(v)
        return tag

    def find_flows(self, sources, sinks):


        flow_list = []
        dumped_sources = set()

        for source in sources:
            for sink in sinks:


                original_manager = self.taint_manager
                self.taint_manager = TaintEnv()


                tag = self.path_finder.propagate_taint(source)



                source_key = (self.current_entry_point, source.node_type, source.node_id, source.def_stmt_id)
                if source_key not in dumped_sources:
                    dumped_sources.add(source_key)
                    self.save_graph_to_dot(
                        graph=self.sfg,
                        entry_point=f"{self.current_entry_point}_taint_{source.def_stmt_id}",
                        phase_id=ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS,
                        taint_manager=self.taint_manager
                    )
                    self.dump_tainted_sfg_by_method(
                        source=source,
                        phase_id=ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS,
                        taint_manager=self.taint_manager
                    )

                sink_tag, vuln_type = self.rule_applier.get_sink_tag_by_rules(sink)

                if (sink_tag & tag) != 0:
                    flow = self.path_finder.reconstruct_define_use_path(source, sink)
                    flow.vuln_type = vuln_type
                    flow_list.append(flow)


                self.taint_manager = original_manager

        return flow_list
    def save_graph_to_dot(self, graph, entry_point, phase_id, taint_manager=None):

        if not (getattr(self.options, "graph", False) or getattr(self.options, "complete_graph", False)):
            return

        if graph is None or len(graph) == 0:
            return

        dumper = SFGDumper(
            loader=self.loader,
            options=self.options,
            phase_id=phase_id,
            entry_point=entry_point,
            symbol_state_space=None,
            graph=graph,
            taint_manager=taint_manager
        )

        try:
            file_name = dumper.dump_to_file()
            if self.options.debug:
                util.debug(">>> Write state flow graph to dot file: ", file_name)
        except Exception:
            if not self.options.quiet:
                util.error("An error occurred while writing state flow graph to dot file.")
                traceback.print_exc()

    def _get_node_method_id(self, node):

        try:
            if getattr(node, "def_stmt_id", -1) is None or node.def_stmt_id < 0:
                return -1
            return self.loader.convert_stmt_id_to_method_id(node.def_stmt_id)
        except Exception:
            return -1

    def split_sfg_by_method(self, graph):

        method_to_nodes = {}
        for n in graph.nodes():
            mid = self._get_node_method_id(n)
            method_to_nodes.setdefault(mid, set()).add(n)

        method_to_subgraph = {}
        for mid, nodes in method_to_nodes.items():
            sg = nx.MultiDiGraph()
            sg.add_nodes_from(nodes)
            method_to_subgraph[mid] = sg

        for u, v, data in graph.edges( data=True):
            mu = self._get_node_method_id(u)
            mv = self._get_node_method_id(v)
            if mu != mv:
                continue
            method_to_subgraph[mu].add_edge(u, v, **data)

        return method_to_subgraph

    def dump_tainted_sfg_by_method(self, source, phase_id, taint_manager):

        if not (getattr(self.options, "graph", False) or getattr(self.options, "complete_graph", False)):
            return

        method_to_graph = self.split_sfg_by_method(self.sfg)
        for method_id, sub_g in method_to_graph.items():

            if method_id >= 0:
                method_name = self.loader.convert_method_id_to_method_name(method_id)
                method_suffix = f"m{method_id}_{method_name}"
            else:
                method_suffix = "m_unknown"

            self.save_graph_to_dot(
                graph=sub_g,
                entry_point=f"{self.current_entry_point}_taint_{source.def_stmt_id}_{method_suffix}",
                phase_id=phase_id,
                taint_manager=taint_manager,
            )

    def get_all_forward_nodes(self, source):

        worklist = deque([source])
        visited = {source}

        while worklist:
            u = worklist.popleft()

            if u.node_type == SFG_NODE_KIND.SYMBOL:

                for v in self.sfg.successors(u):
                    if v in visited: continue
                    edge_data = self.sfg.get_edge_data(u, v)
                    if not edge_data: continue
                    for data in edge_data.values():
                        etype = data.edge_type
                        if etype in (SFG_EDGE_KIND.SYMBOL_STATE, SFG_EDGE_KIND.SYMBOL_IS_USED,
                                     SFG_EDGE_KIND.SYMBOL_FLOW, SFG_EDGE_KIND.INDIRECT_SYMBOL_FLOW):
                            visited.add(v)
                            worklist.append(v)
                            break

            elif u.node_type == SFG_NODE_KIND.STATE:

                for v in self.sfg.predecessors(u):
                    if v in visited: continue
                    edge_data = self.sfg.get_edge_data(v, u)
                    if not edge_data: continue
                    for data in edge_data.values():
                        if data.edge_type == SFG_EDGE_KIND.SYMBOL_STATE:
                            visited.add(v)
                            worklist.append(v)
                            break

                for v in self.sfg.successors(u):
                    if v in visited: continue
                    edge_data = self.sfg.get_edge_data(u, v)
                    if not edge_data: continue
                    for data in edge_data.values():
                        etype = data.edge_type
                        if etype in (SFG_EDGE_KIND.STATE_INCLUSION, SFG_EDGE_KIND.INDIRECT_STATE_INCLUSION,
                                     SFG_EDGE_KIND.STATE_COPY):
                            visited.add(v)
                            worklist.append(v)
                            break

            elif u.node_type == SFG_NODE_KIND.STMT:

                for v in self.sfg.successors(u):
                    if v in visited: continue
                    edge_data = self.sfg.get_edge_data(u, v)
                    if not edge_data: continue
                    for data in edge_data.values():
                        if data.edge_type == SFG_EDGE_KIND.SYMBOL_IS_DEFINED:
                            visited.add(v)
                            worklist.append(v)
                            break
        return visited

    def get_all_backward_nodes(self, sink_symbol):

        if sink_symbol.node_type != SFG_NODE_KIND.SYMBOL:
            return set()

        worklist = deque([sink_symbol])
        visited = {sink_symbol}

        while worklist:
            u = worklist.popleft()


            for v in self.sfg.predecessors(u):
                if v in visited: continue
                edge_data = self.sfg.get_edge_data(v, u)
                if not edge_data: continue

                is_related = False
                for data in edge_data.values():
                    etype = data.edge_type
                    if u.node_type == SFG_NODE_KIND.SYMBOL:

                        if etype in (SFG_EDGE_KIND.SYMBOL_IS_DEFINED,
                                     SFG_EDGE_KIND.SYMBOL_FLOW, SFG_EDGE_KIND.INDIRECT_SYMBOL_FLOW):
                            is_related = True
                    elif u.node_type == SFG_NODE_KIND.STMT:

                        if etype == SFG_EDGE_KIND.SYMBOL_IS_USED:
                            is_related = True

                    if is_related:

                        if v.node_type in (SFG_NODE_KIND.SYMBOL, SFG_NODE_KIND.STMT):
                            visited.add(v)
                            worklist.append(v)
                        break
        return visited

    def print_and_write_flows(self, flows):
        print(f"Found {len(flows)} taint flows.")
        flow_json = []

        for each_flow in flows:
            source_stmt = self.loader.get_stmt_gir(each_flow.source_stmt_id)
            source_gir = get_gir_str(source_stmt)
            source_method_id = self.loader.convert_stmt_id_to_method_id(each_flow.source_stmt_id)
            source_method_name = self.loader.convert_method_id_to_method_name(source_method_id)

            sink_stmt = self.loader.get_stmt_gir(each_flow.sink_stmt_id)
            sink_gir = get_gir_str(sink_stmt)
            sink_line_no = int(sink_stmt.start_row)
            source_line_no = int(source_stmt.start_row)

            source_unit_id = self.loader.convert_stmt_id_to_unit_id(each_flow.source_stmt_id)
            source_file_path = self.loader.convert_unit_id_to_unit_path(source_unit_id)
            sink_unit_id = self.loader.convert_stmt_id_to_unit_id(each_flow.sink_stmt_id)
            sink_file_path = self.loader.convert_unit_id_to_unit_path(sink_unit_id)

            print(f"Found a flow to sink {sink_gir} on line {sink_line_no + 1}")
            print("\tSource :", source_gir, f"(in {source_method_name})")

            line_no = -1
            path_parent_source_node_list = []
            path_parent_source_file_node_list = []
            for node in reversed(each_flow.parent_to_source):
                stmt_id = node.def_stmt_id
                stmt = self.loader.get_stmt_gir(stmt_id)

                if stmt is None or not isinstance(stmt.start_row, (int, float)) or not math.isfinite(stmt.start_row):
                    continue
                if stmt.start_row == line_no:
                    continue
                line_no = stmt.start_row
                gir_str = get_gir_str(stmt)

                method_id = self.loader.convert_stmt_id_to_method_id(stmt_id)
                method_name = self.loader.convert_method_id_to_method_name(method_id)
                path_node = "(" + gir_str + ")" + " on line " + str(int(line_no) + 1)
                unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
                file_path = self.loader.convert_unit_id_to_unit_path(unit_id)
                path_node_in_file = {
                    "start_line": int(stmt.start_row + 1),
                    "end_line": int(stmt.end_row + 1) if isinstance(stmt.end_row, (int, float)) and math.isfinite(stmt.end_row) else int(stmt.start_row + 1),
                    "file_path": file_path,
                    "gir": gir_str,
                    "stmt_id": int(stmt_id),
                }
                path_parent_source_node_list.append(path_node)
                path_parent_source_file_node_list.append(path_node_in_file)

            line_no = -1
            path_parent_sink_node_list = []
            path_parent_sink_file_node_list = []
            for node in each_flow.parent_to_sink:
                stmt_id = node.def_stmt_id
                stmt = self.loader.get_stmt_gir(stmt_id)
                if stmt is None or not isinstance(stmt.start_row, (int, float)) or not math.isfinite(stmt.start_row):
                    continue
                if stmt.start_row == line_no:
                    continue
                line_no = stmt.start_row
                gir_str = get_gir_str(stmt)

                method_id = self.loader.convert_stmt_id_to_method_id(stmt_id)
                method_name = self.loader.convert_method_id_to_method_name(method_id)
                path_node = "(" + gir_str + ")" + " on line " + str(int(line_no) + 1)
                unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
                file_path = self.loader.convert_unit_id_to_unit_path(unit_id)
                path_node_in_file = {
                    "start_line": int(stmt.start_row + 1),
                    "end_line": int(stmt.end_row + 1) if isinstance(stmt.end_row, (int, float)) and math.isfinite(stmt.end_row) else int(stmt.start_row + 1),
                    "file_path": file_path,
                    "gir": gir_str,
                    "stmt_id": int(stmt_id),
                }
                path_parent_sink_node_list.append(path_node)
                path_parent_sink_file_node_list.append(path_node_in_file)

            if not self.is_sublist(path_parent_source_node_list, path_parent_sink_node_list):
                path_parent_sink_node_list = path_parent_source_node_list + path_parent_sink_node_list
            if not self.is_sublist(path_parent_source_file_node_list, path_parent_sink_file_node_list):
                path_parent_sink_file_node_list = path_parent_source_file_node_list + path_parent_sink_file_node_list
            print("\t\tData Flow:", path_parent_sink_node_list)

            flow_json.append({
                "source_stmt_id": int(each_flow.source_stmt_id),
                "sink_stmt_id": int(each_flow.sink_stmt_id),
                "source": source_gir,
                "sink": sink_gir,
                "source_line": source_line_no + 1,
                "sink_line": sink_line_no + 1,
                "source_file_path": source_file_path,
                "sink_file_path": sink_file_path,
                "data_flow": path_parent_sink_file_node_list,
                "vuln_type": each_flow.vuln_type,
            })

        output_dir = os.path.join(self.options.workspace, config.TAINT_OUTPUT_DIR)
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "taint_data_flow.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(flow_json, f, ensure_ascii=False, indent=2)
        print(f"Wrote taint data flows to {output_file}")

    def is_sublist(self, sub, lst):
        return str(sub)[1:-1] in str(lst)[1:-1]

    def run(self):
        if not self.options.quiet:
            print("\n########### # Phase IV: Taint Analysis # ##########")

        all_flows = []
        skipped_entry_points = []
        for method_id in self.loader.get_all_method_ids():
            self.current_entry_point = method_id
            try:
                self.sfg = self.loader.get_global_sfg_by_entry_point(method_id)
                self._update_sfg(self.sfg)
            except (ArrowInvalid, OSError, FileNotFoundError) as exc:
                skipped_entry_points.append(method_id)
                print(f"[WARNING] Skip taint entry point {method_id}: {exc}")
                continue
            if not self.sfg:
                continue
            self.taint_manager = TaintEnv()
            sources = self.find_sources()
            sinks = self.find_sinks()

            flows = self.find_flows(sources, sinks)
            all_flows.extend(flows)

        if len(all_flows) == 0:
            print("No taint flows found.")
        else:
            if not self.options.quiet:
                self.print_and_write_flows(all_flows)

        if skipped_entry_points:
            print(f"Skipped {len(skipped_entry_points)} entry points due to unreadable SFG bundles.")
        return self
