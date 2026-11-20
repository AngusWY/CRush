

from pathlib import Path
import os,sys
import pprint
from ctypes import c_void_p, cdll
import tree_sitter
import importlib
from lian.events.event_manager import EventManager
from lian.util import util
from lian.config import lang_config
from lian.config import config
from lian.config.constants import EVENT_KIND

from lian.events.handler_template import EventData
from lian.util.loader import Loader
from lian.incremental.unit_level_incremental_checker import UnitLevelIncrementalChecker
from lian.lang.code_preprocessor import prepare_code

EXTENSIONS_LANG = lang_config.EXTENSIONS_LANG


OPTIONAL_CLAUSE_BODY_KEYS = {"else_body", "elsebody", "catch_body", "final_body", "finally_body"}

def determine_lang_by_path(file_path):
    ext = os.path.splitext(file_path)[1]
    return EXTENSIONS_LANG.get(ext, None)


def is_empty_strict_version(node):

    if not node:
        return True

    if isinstance(node, list) or isinstance(node, set):
        for child in node:
            if not is_empty(child):
                return False
        return True

    elif isinstance(node, dict):
        for myvalue in node.values():
            if not is_empty(myvalue):
                return False
        return True

    return False

def is_empty(node):

    if not node:
        return True

    if isinstance(node, list) or isinstance(node, set):
        for child in node:
            if not is_empty(child):
                return False
        return True

    elif isinstance(node, dict):
        if len(node) > 0:
            return False
        return True

    return False


class GIRProcessing:
    def __init__(self, node_id):
        self.node_id = node_id

    def assign_id(self):

        previous = self.node_id
        self.node_id += 1
        return previous

    def get_id_from_node(self, node):

        if "stmt_id" not in node:
            node["stmt_id"] = self.assign_id()
        return node["stmt_id"]

    def init_stmt_id(self, stmt, parent_stmt_id):
        stmt["parent_stmt_id"] = parent_stmt_id
        stmt["stmt_id"] = self.assign_id()

    def is_gir_format(self, stmts):

        if stmts and isinstance(stmts, list) and len(stmts) > 0 \
           and stmts[0] and isinstance(stmts[0], dict):
            return True

        return False

    def flatten_stmt(self, stmt, last_node: dict, dataframe, parent_stmt_id = 0):

        if not isinstance(stmt, dict):
            util.error("[Input format error] The input node should not be a dictionary: " + str(stmt))
            return



        flattened_node = {}
        dataframe.append(flattened_node)



        flattened_node["operation"] = list(stmt.keys())[0]
        stmt_content = stmt[flattened_node["operation"]]

        self.init_stmt_id(flattened_node, parent_stmt_id)

        if flattened_node["operation"] in ["assign_stmt", "call_stmt"] and "operation" in last_node and last_node["operation"] == "variable_decl":
            last_node["original_stmt"] = flattened_node["stmt_id"]

        if not isinstance(stmt_content, dict):
            return

        for mykey, myvalue in stmt_content.items():
            if isinstance(myvalue, list):
                if not self.is_gir_format(myvalue):
                    if "body" in mykey and mykey not in OPTIONAL_CLAUSE_BODY_KEYS:
                        block_id = self.flatten_block(myvalue, flattened_node["stmt_id"], dataframe)
                        flattened_node[mykey] = block_id
                        continue
                    if len(myvalue) == 0:
                        flattened_node[mykey] = None
                    else:
                        flattened_node[mykey] = str(myvalue)
                else:
                    block_id = self.flatten_block(myvalue, flattened_node["stmt_id"], dataframe)
                    flattened_node[mykey] = block_id

            elif isinstance(myvalue, dict):
                util.error_and_quit("[Input format error] Dictionary is not allowed: " + str(myvalue))
                continue
            else:
                flattened_node[mykey] = myvalue

        return flattened_node

    def flatten_block(self, block, parent_stmt_id, dataframe: list):

        block_id = self.assign_id()
        dataframe.append({"operation": "block_start", "stmt_id": block_id, "parent_stmt_id": parent_stmt_id})
        last_node = {}
        for child in block:
            last_node = self.flatten_stmt(child, last_node, dataframe, block_id)

        dataframe.append({"operation": "block_end", "stmt_id": block_id, "parent_stmt_id": parent_stmt_id})
        return block_id

    def flatten_gir(self, stmts):

        flattened_nodes = []
        last_node = {}
        for stmt in stmts:
            last_node = self.flatten_stmt(stmt, last_node, flattened_nodes)

        return flattened_nodes

    def flatten(self, stmts):

        if not self.is_gir_format(stmts):
            util.error_and_quit("The input fromat of GLang IR is not correct.")
            return
        flattened_nodes = self.flatten_gir(stmts)
        return (self.node_id, flattened_nodes)

class GIRParser:
    def __init__(self, options, event_manager, loader, output_path):
        self.options = options
        self.event_manager = event_manager
        self.loader = loader

        self.accumulated_rows = []
        self.output_path = output_path
        self.max_rows = config.MAX_ROWS
        self.count = 0
        self.ananymous_func_to_scope = {}

    def obtain_ast_parser(self, lang: lang_config.LangConfig):
        try:
            lib = cdll.LoadLibrary(lang.so_path)
            function_name = lang.name if lang.name != "csharp" else "c_sharp"
            lang_function = getattr(lib, f"tree_sitter_{function_name}")
            lang_function.restype = c_void_p
            lang_id = lang_function()
            lang_inter = tree_sitter.Language(lang_id)
            tree_sitter_parser = tree_sitter.Parser(lang_inter)
            return tree_sitter_parser
        except ValueError as e:
            if "Incompatible Language version" in str(e):
                util.error_and_quit(
                    f"Error: {e}\n"
                    f"❌ The dependency 'tree-sitter' is not corrent. Please upgrade the 'tree-sitter' Python package:\n"
                    f"      pip install -r requirements.txt\n"
                )
                sys.exit(-1)
            else:
                util.error_and_quit(f"ValueError when loading language '{lang.name}': {e}")
        except Exception as e:
            util.error_and_quit(f"Failed to load AST parser for language '{lang.name}': {e}")

    def parse(self, unit_info, file_path, lang_option, lang_table):

        if lang_option is None:
            return

        lang = None
        for language in lang_table:
            if language.name == lang_option:
                lang = language
                break
        if not lang:
            util.error_and_quit("Unsupported language: " + self.options.lang)

        ast_parser = self.obtain_ast_parser(lang)
        if not ast_parser:
            util.error_and_quit("Failed to obtain AST parser for language: " + lang_option)

        code = None
        tree = None
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()
        except:
            util.error("Failed to read file:", file_path)
            return

        if util.is_empty(code):
            return

        if not self.options.strict_parse_mode:
            if f"{config.DEFAULT_WORKSPACE}/{config.EXTERNS_DIR}" in file_path:
                event = EventData(lang_option, EVENT_KIND.MOCK_SOURCE_CODE_READY, code)
                self.event_manager.notify(event)
                code = event.out_data

            event = EventData(lang_option, EVENT_KIND.ORIGINAL_SOURCE_CODE_READY, code)
            self.event_manager.notify(event)
            code = event.out_data

        try:
            tree = ast_parser.parse(bytes(code, 'utf8'))
        except:
            util.error("Failed to parse AST:", file_path)
            return

        gir_statements = []
        parser = lang.parser(self.options, unit_info)
        parser.ast_parser = ast_parser
        parser.parse_gir(tree.root_node, gir_statements)
        self.ananymous_func_to_scope = getattr(parser, "ananymous_func_to_scope", {})
        return gir_statements

    def deal_with_file_unit(self, current_node_id, unit_info, file_unit, lang_table):

        lang_option = determine_lang_by_path(file_unit)

        if not self.options.quiet:
            print("GIR-Parsing:", file_unit)

        gir_statements = self.parse(unit_info, file_unit, lang_option, lang_table = lang_table)
        if not gir_statements:
            return (current_node_id, None)
        if self.options.debug and self.options.print_stmts:
            pprint.pprint(gir_statements, compact=True, sort_dicts=False)

        event = EventData(lang_option, EVENT_KIND.UNFLATTENED_GIR_LIST_GENERATED, gir_statements)
        self.event_manager.notify(event)
        if lang_option == "abc":
            event.out_data = prepare_code(self.ananymous_func_to_scope).run(event.out_data)
        current_node_id, flatten_nodes = GIRProcessing(current_node_id).flatten(event.out_data)
        if not flatten_nodes:
            return (current_node_id, flatten_nodes)

        event = EventData(lang_option, EVENT_KIND.GIR_LIST_GENERATED, flatten_nodes)
        self.event_manager.notify(event)
        if lang_option == "abc":
            event.out_data = prepare_code().find_lex_var(event.out_data)
        if self.options.debug and self.options.print_stmts:
            pprint.pprint(event.out_data, compact=True, sort_dicts=False)

        return (current_node_id, event.out_data)

    def add_unit_gir(self, unit_info, flatten_nodes):

        if is_empty(flatten_nodes):
            return

        unit_id = unit_info.module_id
        for node in flatten_nodes:
            node["unit_id"] = unit_id
        self.loader.save_unit_gir(unit_id, flatten_nodes)

class LangAnalysis:
    def __init__(self, lian):
        self.options = lian.options
        self.event_manager: EventManager = lian.event_manager
        self.loader: Loader = lian.loader
        self.lang_table = lian.lang_table

    def init_start_stmt_id(self):

        symbol_table = self.loader.get_module_symbol_table()
        result = max(symbol_table.module_id)
        return self.adjust_node_id(result)

    def adjust_node_id(self, node_id):




        node_id += config.MIN_ID_INTERVAL
        remainder = node_id % 10
        if remainder != 0:
            node_id += (10 - remainder)
        return node_id

    def run(self):

        if not self.options.quiet:
            print("\n###########  # Language Parsing #  ###########")

        gir_parser = GIRParser(
            self.options,
            self.event_manager,
            self.loader,
            os.path.join(self.options.workspace, config.FRONTEND_DIR)
        )
        all_units = self.loader.get_all_unit_info()
        if len(all_units) == 0:
            util.error_and_quit("No files found for analysis.")

        current_node_id = self.init_start_stmt_id()

        units_to_analyze = all_units
        if self.options.incremental:
            unit_level_checker = UnitLevelIncrementalChecker.unit_level_incremental_checker()
            units_to_analyze = []
            for unit_info in all_units:
                current_node_id, previous_results = unit_level_checker.previous_lang_analysis_results(unit_info, current_node_id)
                if previous_results:
                    gir_parser.add_unit_gir(unit_info, previous_results)
                    current_node_id = self.adjust_node_id(current_node_id)

                else:
                    units_to_analyze.append(unit_info)

        for unit_info in units_to_analyze:
            unit_path = ""
            if self.options.strict_parse_mode:
                unit_path = unit_info.original_path
            else:
                unit_path = unit_info.unit_path
            current_node_id, gir = gir_parser.deal_with_file_unit(
                current_node_id, unit_info, unit_path, lang_table = self.lang_table
            )
            gir_parser.add_unit_gir(unit_info, gir)
            current_node_id = self.adjust_node_id(current_node_id)

        self.loader.save_max_gir_id(current_node_id)
