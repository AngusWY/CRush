

import os
import ast
import yaml
import dataclasses,pprint
import lian.util.data_model as dm

from lian.util import util
from lian.config import config
from lian.util.loader import Loader
from lian.config.constants import (LIAN_SYMBOL_KIND)

@dataclasses.dataclass
class EntryPointRule:
    lang: str = ""
    unit_id: int = -1
    unit_path: str = ""
    unit_name: str = ""
    method_id: int = -1
    method_list: list[str] = dataclasses.field(default_factory=list)
    exclude_paths: list[str] = dataclasses.field(default_factory=list)
    attrs: list[str] = dataclasses.field(default_factory=list)
    args: str = ""
    return_type: str = ""

    def __post_init__(self):
        self.check_availablility()

    def check_availablility(self):
        self.is_lang_available = util.is_available(self.lang)
        self.is_unit_name_available = util.is_available(self.unit_name)
        self.is_unit_path_available = util.is_available(self.unit_path)
        self.is_method_list_available = util.is_available(self.method_list)
        self.is_exclude_paths_available = util.is_available(self.exclude_paths)
        self.is_attrs_available = util.is_available(self.attrs)
        self.is_args_available = util.is_available(self.args)
        self.is_return_type_available = util.is_available(self.return_type)

class EntryPointGenerator:
    def __init__(self, options, event_manager, loader) -> None:
        self.options = options
        self.event_manager = event_manager
        self.loader:Loader = loader
        self.entry_point_rules = []
        self.entry_point_results = set()
        self._load_settings()

    def _parse_config_file(self, file_path):

        if not os.path.isfile(file_path):
            util.error("Failed to open entry point file: " + file_path)
            return

        data = None
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)
            if data is None:
                util.error("Failed to load entry point file: " + file_path)
                return

        for line in data:
            try:
                self.entry_point_rules.append(
                    EntryPointRule(
                        **line
                    )
                )
            except Exception as e:
                util.error_and_quit(f"Failed to parse entry point file ({file_path}), error: {e}")

    def _load_settings(self):
        for root, dirs, files in os.walk(self.options.default_settings):
            for file_name in files:
                processing_flag, _ = util.check_file_processing_flag_and_extract_lang(file_name, config.ENTRY_POINTS_FILE)
                if not processing_flag:
                    continue

                self._parse_config_file(os.path.join(root, file_name))

    def filter_rule_by_unit_info(self, unit_info):
        unit_name = os.path.basename(unit_info.unit_path)
        candidate_rules = []

        for rule in self.entry_point_rules:

            if rule.is_lang_available and rule.lang != unit_info.lang:
                continue


            if rule.unit_id >= 0 and rule.unit_id != unit_info.module_id:
                continue


            if rule.is_unit_name_available and rule.unit_name not in unit_name:
                continue


            if rule.is_unit_path_available and rule.unit_path not in unit_info.unit_path:
                continue


            if rule.is_exclude_paths_available and any(
                ex in unit_info.unit_path for ex in rule.exclude_paths
            ):
                continue


            candidate_rules.append(rule)

        return candidate_rules

    def check_rules(self, unit_info, unit_scope, candidate_rules):
        all_method_scopes = unit_scope.query_index_column_value("scope_kind", LIAN_SYMBOL_KIND.METHOD_KIND)
        for scope in all_method_scopes:
            name = scope.name if util.is_available(scope.name) else ""
            attrs = scope.attrs if util.is_available(scope.attrs) else ""
            args = ""
            return_type = ""

            matched = False
            for rule in candidate_rules:



                if rule.method_id >= 0:
                    if rule.method_id == scope.stmt_id:
                        matched = True
                        break
                    else:
                        continue


                if rule.is_method_list_available and name not in rule.method_list:
                    continue


                if rule.is_attrs_available:
                    if not attrs or not all(attr in attrs for attr in rule.attrs):
                        continue


                if rule.is_args_available and rule.args != args:
                    continue


                if rule.is_return_type_available and rule.return_type != return_type:
                    continue


                matched = True
                break

            if matched:
                self.entry_point_results.add(scope.stmt_id)

    def collect_entry_points_from_unit_scope(self, unit_info, unit_scope):

        candidate_rules = self.filter_rule_by_unit_info(unit_info)

        if not candidate_rules:
            return

        self.check_rules(unit_info, unit_scope, candidate_rules)


        self.loader.save_entry_points(self.entry_point_results)

