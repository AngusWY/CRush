

import re
from tree_sitter import Node
from lian.lang import common_parser
from lian.util import util
from lian.config.constants import LIAN_INTERNAL

import os

class Parser(common_parser.Parser):
    def obtain_literal_handler(self, node):
        LITERAL_MAP = {
            "number"                            : self.regular_number_literal,
            "true"                              : self.regular_literal,
            "false"                             : self.regular_literal,
            "null"                              : self.regular_literal,
            "undefined"                         : self.regular_literal,
            "regex"                             : self.regular_literal,
            "template_string"                   : self.template_string,
            "string"                            : self.string_literal,
            "string_fragment"                   : self.string_literal,
            "escape_sequence"                   : self.string_literal,
            "summary_string"                    : self.string_literal,
            "summary_substitution"              : self.summary_substitution,
            "this"                              : self.this_literal,
            "super"                             : self.super_literal,
        }

        return LITERAL_MAP.get(node.type, None)

    def check_declaration_handler(self, node):
        DECLARATION_HANDLER_MAP = {
            "function_declaration"            : self.function_declaration,
            "generator_function_declaration"  : self.function_declaration,
            "class_declaration"               : self.class_declaration,
            "lexical_declaration"             : self.variable_declaration,
            "variable_declaration"            : self.variable_declaration,
        }

        return DECLARATION_HANDLER_MAP.get(node.type, None)

    def check_expression_handler(self, node):
        EXPRESSION_HANDLER_MAP = {
            "subscript_expression"              : self.subscript_expression,
            "member_expression"                 : self.member_expression,
            "object"                            : self.new_object,

            "array"                             : self.new_array,
            "function_expression"               : self.function_declaration,
            "arrow_function"                    : self.function_declaration,
            "generator_function"                : self.function_declaration,
            "class"                             : self.class_declaration,

            "call_expression"                   : self.call_expression,
            "decorator_call_expression"         : self.call_expression,

            "assignment_expression"             : self.assignment_expression,
            "augmented_assignment_expression"   : self.assignment_expression,
            "await_expression"                  : self.await_expression,
            "unary_expression"                  : self.unary_expression,
            "binary_expression"                 : self.binary_expression,
            "ternary_expression"                : self.ternary_expression,
            "update_expression"                 : self.update_expression,
            "new_expression"                    : self.new_expression,
            "yield_expression"                  : self.yield_expression,
        }

        return EXPRESSION_HANDLER_MAP.get(node.type, None)

    def check_statement_handler(self, node):
        STATEMENT_HANDLER_MAP = {
            "export_statement"            : self.export_statement,
            "import_statement"            : self.import_statement,

            "if_statement"                : self.if_statement,
            "switch_statement"            : self.switch_statement,
            "for_statement"               : self.for_statement,
            "for_in_statement"            : self.each_statement,
            "while_statement"             : self.while_statement,
            "do_statement"                : self.dowhile_statement,
            "try_statement"               : self.try_statement,
            "with_statement"              : self.with_statement,
            "break_statement"             : self.break_statement,
            "continue_statement"          : self.continue_statement,
            "return_statement"            : self.return_statement,
            "throw_statement"             : self.throw_statement,
            "empty_statement"             : self.empty_statement,
            "labeled_statement"           : self.labeled_statement,
        }
        return STATEMENT_HANDLER_MAP.get(node.type, None)

    def parse_path(self, path):


        if path.startswith('./'):
            path = path[2:]


        dir_path, full_filename = os.path.split(path)


        directories = []


        if os.path.isabs(path):
            dir_path = dir_path[1:]


        while dir_path:
            dir_path, dir_name = os.path.split(dir_path)

            if dir_name and dir_name != '".' and dir_name!= "'.":
                directories.append(dir_name)


        directories.reverse()


        dirpath = '.'.join(directories) if directories else ''


        filename, _ = os.path.splitext(full_filename)

        return dirpath, filename

    def pack_args(self, node, statements: list):
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {
            "new_array": {
                "target": tmp_var
            }
        })

        meet_splat = False
        for index, arg in enumerate(node.named_children):
            if self.is_comment(arg):
                continue

            if arg.type == "spread_element":
                meet_splat = True
                shadow_expr = self.parse(arg, statements)
                self.append_stmts(statements, node, {"array_extend": {"array": tmp_var, "source": shadow_expr}})
            else:
                if meet_splat:
                    shadow_expr = self.parse(arg, statements)
                    self.append_stmts(statements, node, {"array_append": {"array": tmp_var, "source": shadow_expr}})
                else:
                    shadow_expr = self.parse(arg, statements)
                    self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": shadow_expr}})

        return tmp_var

    def is_comment(self, node):
        return node.type == "comment"



    def is_identifier(self, node):
        identifier_list = [
            "identifier",
            "property_identifier",
            "private_property_identifier"
        ]
        return node.type in identifier_list

    def regular_number_literal(self, node: Node, statements: list, replacement: list):
        value = self.read_node_text(node)
        value = self.common_eval(value)
        return str(value)

    def regular_literal(self, node: Node, statements: list, replacement: list):
        return self.read_node_text(node)

    def this_literal(self, node: Node, statements: list, replacement: list):
        return self.global_this()

    def super_literal(self, node: Node, statements: list, replacement: list):
        return self.global_super()

    def string_literal(self, node: Node, statements: list, replacement: list):
        replacement = []
        for child in node.named_children:
            self.parse(child, statements, replacement)

        ret = self.read_node_text(node).replace('`', '"')
        if replacement:

            for r in replacement:
                (expr, value) = r
                ret = ret.replace("${" + self.read_node_text(expr) + "}", "${" + value + "}")

        ret = self.handle_hex_string(ret)
        return self.escape_string(ret)

    def template_string(self, node: Node, statements: list, replacement: list):
        last_assign_result = ""
        if node.named_child_count >= 2:
            for index in range(len(node.named_children)):
                tmp_var = self.tmp_variable()
                shadow_oprand = self.parse(node.named_children[index], statements)
                if index == 0:
                    last_assign_result = shadow_oprand
                    continue
                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "+", "operand": last_assign_result, "operand2": shadow_oprand}})
                last_assign_result = tmp_var
            return tmp_var

        else:
            for child in node.named_children:
                tmp_var = self.tmp_variable()
                shadow_oprand = self.parse(child, statements)
                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_oprand}})
                return tmp_var

    def summary_substitution(self, node: Node, statements: list, replacement: list):
        expr = node.named_children[0]
        shadow_expr = self.parse(expr, statements)
        replacement.append((expr, shadow_expr))
        return shadow_expr

    def binary_expression(self, node: Node, statements: list):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator = self.find_child_by_field(node, "operator")

        shadow_operator = self.read_node_text(operator)

        shadow_left = self.parse(left, statements)
        shadow_right = self.parse(right, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": tmp_var, "operator": shadow_operator, "operand": shadow_left, "operand2": shadow_right
            }})

        return tmp_var

    def unary_expression(self, node: Node, statements: list):
        operand = self.find_child_by_field(node, "argument")
        shadow_operand = self.parse(operand, statements)
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator)

        tmp_var = self.tmp_variable()

        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_operand}})
        return tmp_var

    def ternary_expression(self, node: Node, statements: list):
        condition = self.find_child_by_field(node, "condition")
        consequence = self.find_child_by_field(node, "consequence")
        alternative = self.find_child_by_field(node, "alternative")

        condition = self.parse(condition, statements)

        then_body = []
        else_body = []
        tmp_var = self.tmp_variable()

        expr1 = self.parse(consequence, then_body)
        then_body.append({"assign_stmt": {"target": tmp_var, "operand": expr1}})

        expr2 = self.parse(alternative, else_body)
        else_body.append({"assign_stmt": {"target": tmp_var, "operand": expr2}})

        self.append_stmts(statements, node, {"if_stmt": {"condition": condition, "then_body": then_body, "else_body": else_body}})
        return tmp_var

    def update_expression(self, node: Node, statements: list):
        shadow_node = self.read_node_text(node)

        operator = "-"
        if "+" == shadow_node[0] or "+" == shadow_node[-1]:
            operator = "+"

        is_after = False
        if shadow_node[-1] == operator:
            is_after = True

        tmp_var = self.tmp_variable()

        expression = self.find_child_by_field(node, "argument")

        if expression.type == "member_expression":
            shadow_object, field = self.parse_field(expression, statements)

            self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": field}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var2, "operator": operator, "operand": tmp_var, "operand2": "1"}})
            self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": field, "source": tmp_var2}})

            if is_after:
                return tmp_var
            return tmp_var2

        if expression.type == "subscript_expression":
            shadow_array, shadow_index = self.parse_array(expression, statements)

            self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var2, "operator": operator, "operand": tmp_var, "operand2": "1"}})
            self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})

            if is_after:
                return tmp_var
            return tmp_var2

        shadow_expression = self.parse(expression, statements)



        if is_after:
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_expression}})

        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_expression, "operator": operator,
                                           "operand": shadow_expression, "operand2": "1"}})


        if not is_after:
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_expression}})

        return tmp_var

    def assignment_expression(self, node: Node, statements: list):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator).replace("=", "")

        shadow_right = self.parse(right, statements)

        if left.type == "member_expression":
            object = self.find_child_by_field(left, "object")
            field = self.find_child_by_field(left, "property")
            shadow_object, shadow_field = self.parse_field(left, statements)
            if not shadow_operator:

                if shadow_object == "module" and shadow_field == "exports":
                    self.append_stmts(statements, node, {
                        "export_stmt": {
                            "name": shadow_right
                        }
                    })
                    return


                elif shadow_object == "exports":
                    self.append_stmts(statements, node, {
                        "export_stmt": {
                            "name": shadow_right,
                            "alias": shadow_field
                        }
                    })
                    return shadow_field


                elif object.type == "member_expression":
                    object2 = self.find_child_by_field(object, "object")
                    field2 = self.find_child_by_field(object, "property")
                    shadow_object2 = self.read_node_text(object2)
                    shadow_field2 = self.read_node_text(field2)
                    if shadow_object2 == "module" and shadow_field2 == "exports":
                        self.append_stmts(statements, node, {
                            "export_stmt": {"name": shadow_right, "alias": shadow_field}
                        })
                        return shadow_field
                    else:
                        self.append_stmts(statements, node,
                            {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": shadow_right}})
                        return shadow_right


                else:
                    self.append_stmts(statements, node, {
                        "field_write": {
                            "receiver_object": shadow_object,
                            "field": shadow_field,
                            "source": shadow_right
                        }
                    })
                    return shadow_right

            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt":
                                   {"target": tmp_var2, "operator": shadow_operator,
                                    "operand": tmp_var, "operand2": shadow_right}})
            self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": tmp_var2}})

            return tmp_var2

        if left.type == "subscript_expression":
            shadow_array, shadow_index = self.parse_array(left, statements)

            if not shadow_operator:
                self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_right}})
                return shadow_right

            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var2, "operator": shadow_operator,
                                    "operand": tmp_var, "operand2": shadow_right}})
            self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})

            return tmp_var2


        if left.type == "array_pattern":
            index = 0

            previous_was_comma = False
            encountered_open_bracket = False

            for p in left.children:
                if self.is_comment(p):
                    previous_was_comma = False
                    encountered_open_bracket = False
                    continue
                elif p.type == "[" or p.type == "]":
                    previous_was_comma = False
                    encountered_open_bracket = True
                    continue
                elif p.type == ",":
                    if previous_was_comma or encountered_open_bracket:
                        index += 1
                    previous_was_comma = True
                    encountered_open_bracket = False
                    continue
                else:
                    previous_was_comma = False
                    encountered_open_bracket = False
                    elem = self.parse(p, statements)
                    self.append_stmts(statements, node, {"array_read": {"target": elem, "array": shadow_right, "index": str(index)}})
                index += 1

            return shadow_right


        if left.type == "object_pattern":
            for p in left.named_children:
                if self.is_comment(p):
                    continue

                if p.type == "shorthand_property_identifier_pattern":
                    pattern = self.read_node_text(p)

                    self.append_stmts(statements, node, {"field_read": {"target": pattern, "receiver_object": shadow_right, "field": pattern}})
                elif p.type == "pair_pattern":
                    left_child = self.find_child_by_field(p, "key")
                    right_child = self.find_child_by_field(p, "value")

                    shadow_left_child = self.property_name(left_child, statements)
                    shadow_right_child = self.parse(right_child, statements)

                    self.append_stmts(statements, node, {"field_read": {"target": shadow_right_child, "receiver_object": shadow_right, "field": shadow_left_child}})

            return shadow_right

        shadow_left = self.read_node_text(left)
        if not shadow_operator:
            self.append_stmts(statements, node, {"variable_decl": {"name": shadow_left, "attrs": ["global"]}})
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operand": shadow_right}})
        else:
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operator": shadow_operator,
                                               "operand": shadow_left, "operand2": shadow_right}})
        return shadow_left

    def parse_field(self, node: Node, statements: list):
        myobject = self.find_child_by_field(node, "object")
        field = self.find_child_by_field(node, "property")
        shadow_object = self.parse(myobject, statements)
        shadow_field = self.parse(field, statements)

        return (shadow_object, shadow_field)

    def member_expression(self, node: Node, statements: list):
        shadow_object, shadow_field = self.parse_field(node, statements)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})
        return tmp_var

    def parse_array(self, node: Node, statements: list):
        array = self.find_child_by_field(node, "object")
        shadow_object = self.parse(array, statements)

        index = self.find_child_by_field(node, "index")
        shadow_index = self.parse(index, statements)
        return (shadow_object, shadow_index)


    def subscript_expression(self, node: Node, statements: list):
        array = self.find_child_by_field(node, "object")
        shadow_array = self.parse(array, statements)
        subscript = self.find_child_by_field(node, "index")

        if subscript is None:
            tmp_array = self.tmp_variable()
            self.append_stmts(statements, node, {"array_read": {"target": tmp_array, "array": shadow_array, "index": ""}})
            return tmp_array

        tmp_array = self.tmp_variable()
        shadow_index = self.parse(subscript, statements)
        self.append_stmts(statements, node, {"array_read": {"target": tmp_array, "array": shadow_array, "index": shadow_index}})
        shadow_array = tmp_array
        return tmp_array

    def call_expression(self, node: Node, statements: list):
        if node.type == "decorator_call_expression":
            return


        name = self.find_child_by_field(node, "function")
        if name.type == "member_expression":
           shadow_object, shadow_name = self.parse_field(name, statements)
        else:
            shadow_name = self.parse(name, statements)

        args = self.find_child_by_field(node, "arguments")


        positional_args = []
        packed_positional_args = None
        if args.named_child_count > 0:
            spread_elem_children = self.find_children_by_type(args, "spread_element")
            if spread_elem_children:
                packed_positional_args = self.pack_args(args, statements)
            else:
                for child in args.named_children:
                    if child.type not in ["spread_element"]:
                        shadow_expr = self.parse(child, statements)
                        positional_args.append(shadow_expr)

        tmp_return = self.tmp_variable()

        if name.type == "member_expression":
            self.append_stmts(statements, node, {
                "object_call_stmt": {"target": tmp_return, "field": shadow_name, "receiver_object": shadow_object,
                                "positional_args": positional_args,
                        "packed_positional_args": packed_positional_args,}})
        else:
            self.append_stmts(statements, node,
                {
                    "call_stmt": {
                        "target": tmp_return,
                        "name": shadow_name,
                        "positional_args": positional_args,
                        "packed_positional_args": packed_positional_args,
                    }
                }
            )

        return tmp_return


    def new_array(self, node: Node, statements: list):

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": tmp_var}})


        index = 0
        previous_was_comma = False
        encountered_open_bracket = False
        meet_spread = False
        for p in node.children:
            if self.is_comment(p):
                previous_was_comma = False
                encountered_open_bracket = False
                continue
            if p.type == "[" or p.type == "]":
                previous_was_comma = False
                encountered_open_bracket = True
                continue
            if p.type == ",":
                if previous_was_comma or encountered_open_bracket:
                    index += 1
                previous_was_comma = True
                encountered_open_bracket = False
                continue
            previous_was_comma = False
            encountered_open_bracket = False
            if p.type == "spread_element":
                meet_spread = True
                pattern = self.parse(p, statements)
                self.append_stmts(statements, node, {"array_extend": {"array": tmp_var, "source": pattern}})

            else:
                if meet_spread:
                    pattern = self.parse(p, statements)
                    self.append_stmts(statements, node, {"array_append": {"array": tmp_var, "source": pattern}})
                else:
                    pattern = self.parse(p, statements)
                    self.append_stmts(statements, node, {"field_write": {"receiver_object": tmp_var, "field": str(index), "source": pattern}})
            index += 1








        return tmp_var


    def parse_pair(self, node: Node, statements: list):
        key = self.find_child_by_field(node, "key")
        value = self.find_child_by_field(node, "value")

        if key.type == "property_identifier":
            shadow_key = self.read_node_text(key)
        else:
            shadow_key = self.parse(key, statements)
        shadow_value = self.parse(value, statements)

        return (shadow_key, shadow_value)


    def new_object(self, node: Node, statements: list):

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_object": {"data_type": LIAN_INTERNAL.OBJECT, "target": tmp_var}})


        for child in node.named_children:
            if self.is_comment(child):
                continue

            shadow_key = ""
            shadow_value = ""

            if child.type == "pair":

                shadow_key, shadow_value = self.parse_pair(child, statements)
            elif child.type == "method_definition":

                name = self.find_child_by_field(child, "name")
                shadow_key = self.property_name(name, statements)
                shadow_value = self.function_declaration(child, statements)
            elif child.type == "spread_element":
                shadow_key = shadow_value = self.parse(child.named_children[0], statements)
                self.append_stmts(statements, node, {"record_extend": {"record": tmp_var, "source": shadow_key}})
            elif child.type == "shorthand_property_identifier":
                shadow_key = shadow_value = self.read_node_text(child)

                self.append_stmts(statements, node, {"field_read": {"target": shadow_key, "receiver_object": tmp_var, "field": shadow_key}})

            self.append_stmts(statements, node, {"field_write": {"receiver_object": tmp_var, "field": shadow_key, "source": shadow_value}})

        return tmp_var


    def new_expression(self, node: Node, statements: list):
        gir_node = {}

        mytype = self.find_child_by_field(node, "constructor")
        if mytype is None:
            tmp_var = self.tmp_variable()
            gir_node["data_type"] = ""
            gir_node["args"] = []
            gir_node["target"] = tmp_var
            self.append_stmts(statements, node, {"new_object": gir_node})
            return tmp_var
        shadow_mytype = self.read_node_text(mytype)
        gir_node["data_type"] = shadow_mytype

        arguments = self.find_child_by_field(node, "arguments")
        arguments_list = []

        if arguments:
            if arguments.named_child_count > 0:
                for arg in arguments.named_children:
                    if self.is_comment(arg):
                        continue

                    shadow_arg = self.parse(arg, statements)
                    if shadow_arg:
                        arguments_list.append(shadow_arg)

        gir_node["positional_args"] = arguments_list

        tmp_var = self.tmp_variable()
        gir_node["target"] = tmp_var

        self.append_stmts(statements, node, {"new_object": gir_node})
        return tmp_var

    def await_expression(self, node: Node, statements: list):
        expr = node.named_children[0]
        shadow_expr = self.parse(expr, statements)

        self.append_stmts(statements, node, {"await_stmt": {"target": shadow_expr}})
        return shadow_expr

    def yield_expression(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)

        self.append_stmts(statements, node, {"yield_stmt": {"name": shadow_expr}})
        return shadow_expr





    def return_statement(self, node: Node, statements: list):
        shadow_name = "undefined"
        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"return_stmt": {"name": shadow_name}})
        return shadow_name

    def if_statement(self, node: Node, statements: list):
        condition_part = self.find_child_by_field(node, "condition")
        true_part = self.find_child_by_field(node, "consequence")
        false_part = self.find_child_by_field(node, "alternative")

        true_body = []

        shadow_condition = self.parse(condition_part, statements)
        self.parse(true_part, true_body)

        if false_part:
            false_body = []
            self.parse(false_part, false_body)
            self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body, "else_body": false_body}})
        else:
            self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body}})

    def while_statement(self, node: Node, statements: list):
        condition = self.find_child_by_field(node, "condition")
        body = self.find_child_by_field(node, "body")

        new_condition_init = []

        shadow_condition = self.parse(condition, new_condition_init)

        new_while_body = []
        self.parse(body, new_while_body)


        statements.extend(new_condition_init)
        new_while_body.extend(new_condition_init)

        self.append_stmts(statements, node, {"while_stmt": {"condition": shadow_condition, "body": new_while_body}})

    def dowhile_statement(self, node: Node, statements: list):
        body = self.find_child_by_field(node, "body")
        condition = self.find_child_by_field(node, "condition")

        do_body = []
        self.parse(body, do_body)
        shadow_condition = self.parse(condition, do_body)

        self.append_stmts(statements, node, {"dowhile_stmt": {"body": do_body, "condition": shadow_condition}})

    def for_statement(self, node: Node, statements: list):
        init = self.find_child_by_field(node, "initializer")
        condition = self.find_child_by_field(node, "condition")
        update = self.find_child_by_field(node, "increment")

        init_body = []
        condition_init = []
        update_body = []

        self.parse(init, init_body)
        shadow_condition = self.parse(condition, condition_init)
        self.parse(update, update_body)

        for_body = []

        block = self.find_child_by_field(node, "body")
        self.parse(block, for_body)

        self.append_stmts(statements, node, {"for_stmt":
                               {"init_body": init_body,
                                "condition_prebody": condition_init,
                                "condition": shadow_condition,
                                "update_body": update_body,
                                "body": for_body}})

    def each_statement(self, node: Node, statements: list):
        kind = self.find_child_by_field(node, "kind")
        modifiers = self.read_node_text(kind).split()

        name = self.find_child_by_field(node, "left")
        shadow_name = self.parse(name, statements)

        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator)

        receiver = self.find_child_by_field(node, "right")
        shadow_receiver = self.parse(receiver, statements)

        body = self.find_child_by_field(node, "body")
        for_body = []
        self.parse(body, for_body)

        self.append_stmts(statements, node, {"variable_decl": {"attrs": modifiers, "name": shadow_name}})
        if shadow_operator == "in":
            self.append_stmts(statements, node, {
                "forin_stmt": {
                    "attrs": modifiers,
                    "name": shadow_name,
                    "receiver": shadow_receiver,
                    "body": for_body
                }
            })
        else:
            self.append_stmts(statements, node, {
                "for_value_stmt": {
                    "attrs": modifiers,
                    "name": shadow_name,
                    "target": shadow_receiver,
                    "body": for_body
                }
            })


































































    def break_statement(self, node: Node, statements: list):
        shadow_name = ""
        name = self.find_child_by_field(node, "label")
        if name:
            shadow_name = self.read_node_text(name)

        self.append_stmts(statements, node, {"break_stmt": {"name": shadow_name}})

    def continue_statement(self, node: Node, statements: list):
        shadow_name = ""
        name = self.find_child_by_field(node, "label")
        if name:
            shadow_name = self.read_node_text(name)

        self.append_stmts(statements, node, {"continue_stmt": {"name": shadow_name}})

    def try_statement(self, node: Node, statements: list):
        try_op = {}
        try_body = []
        catch_body = []
        finally_body = []


        body = self.find_child_by_field(node, "body")
        self.parse(body, try_body)
        try_op["body"] = try_body


        catch_clause = self.find_child_by_field(node, "handler")
        if catch_clause:
            catch_op = {}
            shadow_catch_clause_body = []

            condition = self.find_child_by_field(catch_clause, "parameter")
            if condition:
                if condition.type == "array_pattern":


                    shadow_condition = self.tmp_variable()
                    shadow_catch_clause_body.append({"parameter_decl": {"attrs": [], "name": shadow_condition}})
                    index = 0

                    previous_was_comma = False
                    encountered_open_bracket = False

                    for p in condition.children:
                        if self.is_comment(p):
                            previous_was_comma = False
                            encountered_open_bracket = False
                            continue
                        elif p.type == "[" or p.type == "]":
                            previous_was_comma = False
                            encountered_open_bracket = True
                            continue
                        elif p.type == ",":
                            if previous_was_comma or encountered_open_bracket:
                                index += 1
                            previous_was_comma = True
                            encountered_open_bracket = False
                            continue
                        else:
                            previous_was_comma = False
                            encountered_open_bracket = False
                            elem = self.parse(p, statements)
                            shadow_catch_clause_body.append({"array_read": {"target": elem, "array": shadow_condition, "index": str(index)}})
                        index += 1

                elif condition.type == "object_pattern":


                    shadow_condition = self.tmp_variable()
                    shadow_catch_clause_body.append({"parameter_decl": {"attrs": [], "name": shadow_condition}})

                    for p in condition.named_children:
                        if self.is_comment(p):
                            continue

                        if p.type == "shorthand_property_identifier_pattern":
                            name = self.read_node_text(p)

                            shadow_catch_clause_body.append({"field_read": {"target": name, "receiver_object": shadow_condition, "field": name}})
                        elif p.type == "pair_pattern":
                            left_child = self.find_child_by_field(p, "key")
                            right_child = self.find_child_by_field(p, "value")

                            shadow_left_child = self.property_name(left_child, statements)
                            shadow_right_child = self.parse(right_child, catch_body)

                            shadow_catch_clause_body.append({"field_read": {"target": shadow_right_child, "receiver_object": shadow_condition, "field": shadow_left_child}})

                else:
                    shadow_condition = self.parse(condition, catch_body)

                catch_op["exception"] = shadow_condition

            catch_clause_body = self.find_child_by_field(catch_clause, "body")
            self.parse(catch_clause_body, shadow_catch_clause_body)
            catch_op["body"] = shadow_catch_clause_body
            catch_body.append({"catch_clause": catch_op})

        try_op["catch_body"] = catch_body


        finally_clause = self.find_child_by_field(node, "finalizer")
        if finally_clause:
            finally_clause_body = self.find_child_by_field(finally_clause, "body")
            self.parse(finally_clause_body, finally_body)
        try_op["final_body"] = finally_body

        self.append_stmts(statements, node, {"try_stmt": try_op})

    def throw_statement(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"throw_stmt": {"name": shadow_expr}})

    def labeled_statement(self, node: Node, statements: list):
        name = self.find_child_by_field(node, "label")

        shadow_name = self.read_node_text(name)
        self.append_stmts(statements, node, {"label_stmt": {"name": shadow_name}})

        stmt = self.find_child_by_field(node, "body")
        self.parse(stmt, statements)

    def with_statement(self, node: Node, statements: list):
        obj = self.find_child_by_field(node, "object")
        body = self.find_child_by_field(node, "body")

        shadow_obj = self.parse(obj, statements)

        with_body = []
        self.parse(body, with_body)


        self.append_stmts(statements, node, {"with_stmt": {"name": shadow_obj, "body": with_body}})

    def switch_statement(self, node: Node, statements: list):
        condition = self.find_child_by_field(node, "value")
        shadow_condition = self.parse(condition, statements)

        switch_block = self.find_child_by_field(node, "body")

        switch_stmt_list = []

        for child in switch_block.named_children:
            if self.is_comment(child):
                continue

            stmts = self.find_children_by_field(child, "body")
            if child.type == "switch_default":
                if len(stmts) == 0:
                    continue

                new_body = []
                for default_stmt in stmts:
                    self.parse(default_stmt, new_body)

                switch_stmt_list.append({"default_stmt": {"body": new_body}})
            else:
                case_condition = self.find_child_by_field(child, "value")
                shadow_case_condition = self.parse(case_condition, statements)

                if len(stmts) == 0:
                    switch_stmt_list.append({"case_stmt": {"condition": shadow_case_condition}})
                    continue

                new_body = []
                for case_stmt in stmts:
                    self.parse(case_stmt, new_body)

                switch_stmt_list.append({"case_stmt": {"condition": shadow_case_condition, "body": new_body}})

        self.append_stmts(statements, node, {"switch_stmt": {"condition": shadow_condition, "body": switch_stmt_list}})

    def import_statement(self, node: Node, statements: list):


        import_clause = self.find_child_by_type(node, "import_clause")
        import_source = self.find_child_by_field(node, "source")

        source_str = self.parse(import_source, statements)

        if source_str is not None:

            if source_str.startswith("\"") and source_str.endswith("\""):
                 source_str = source_str[1:-1]
            source_str = os.path.normpath(source_str)
            if source_str.endswith(".js"):
                source_str = source_str[:-3]
            if source_str.startswith("./"):
                source_str = "." + source_str[2:]
            elif source_str.startswith("../"):
                prefix = "."
                while source_str.startswith("../"):
                    prefix += "."
                    source_str = source_str[3:]
                source_str = prefix + source_str

            source_str = source_str.replace("/", ".")
            source_str = source_str.replace("\\", ".")

        if not import_clause:
            self.append_stmts(statements, node, {"import_stmt": {"module_path": source_str, "attrs": ['init']}})
            return


        for import_clause_child in import_clause.named_children:
            if self.is_comment(import_clause_child):
                continue


            if import_clause_child.type == "identifier":
                shadow_name = self.parse(import_clause_child, statements)
                self.append_stmts(statements, node, {"from_import_stmt": {"name": shadow_name, "source": source_str}})


            elif import_clause_child.type == "namespace_import":
                alias = self.find_child_by_type(import_clause_child, "identifier")
                shadow_alias = self.parse(alias, statements)
                self.append_stmts(statements, node, {"from_import_stmt": {"name": "*", "alias": shadow_alias, "source": source_str}})


            else:
                import_specifiers = self.find_children_by_type(import_clause_child, "import_specifier")

                if len(import_specifiers) == 0:
                    self.append_stmts(statements, node, {"import_stmt": {"module_path": source_str, "attrs": ['init']}})
                else:
                    for specifier in import_specifiers:
                        name = self.find_child_by_field(specifier, "name")
                        shadow_name = self.parse(name, statements)

                        alias = self.find_child_by_field(specifier, "alias")
                        if alias:
                            shadow_alias = self.parse(alias, statements)
                            self.append_stmts(statements, node, {"from_import_stmt": {"name": shadow_name, "alias": shadow_alias, "source": source_str}})
                        else:
                            self.append_stmts(statements, node, {"from_import_stmt": {"name": shadow_name, "source": source_str}})


    def parse_export_clause(self, node, statements, source_str=None):
        export_specifiers = self.find_children_by_type(node, "export_specifier")

        if len(export_specifiers) == 0:


            if source_str:
                self.append_stmts(statements, node, {"import_stmt": {"name": "", "module_path": source_str, "attrs": ['init']}})
        else:
            for specifier in export_specifiers:
                name = self.find_child_by_field(specifier, "name")
                shadow_name = self.parse(name, statements)

                alias = self.find_child_by_field(specifier, "alias")
                shadow_alias = self.parse(alias, statements)
                if source_str != None:
                    self.append_stmts(statements, node, {"from_export_stmt": {"name": shadow_name, "alias": shadow_alias, "source": source_str}})
                else:
                    self.append_stmts(statements, node, {"export_stmt": {"name": shadow_name, "alias": shadow_alias}})

    def export_statement(self, node: Node, statements: list):
        export_source = self.find_child_by_field(node, "source")

        if export_source:
            source_str = self.parse(export_source, statements)
            if source_str is not None:
                source_str = os.path.normpath(source_str)
                if source_str[-4:-1] == ".js":
                    source_str = source_str[:-4]
                    source_str = source_str[1:]
                source_str = source_str.replace("/", ".")
                source_str = source_str.replace("\\", ".")
                for str in source_str:
                    if str != '.':
                        break
                    else:
                        source_str = source_str[1:]
                namespace_export = self.find_child_by_type(node, "namespace_export")

            if namespace_export:

                alias = namespace_export.named_children[-1]
                shadow_alias = self.parse(alias, statements)


                self.append_stmts(statements, node, {"from_export_stmt": {"name": "*", "alias": shadow_alias, "source": source_str}})
            else:
                export_clause = self.find_child_by_type(node, "export_clause")
                if export_clause:


                    self.parse_export_clause(export_clause, statements, source_str)
                else:

                    self.append_stmts(statements, node, {"from_export_stmt": {"name": "*", "source": source_str}})

        else:
            export_clause = self.find_child_by_type(node, "export_clause")
            if export_clause:


                self.parse_export_clause(export_clause, statements)
            else:
                declaration = self.find_child_by_field(node, "declaration")
                if declaration:


                    declared_list = self.parse(declaration, statements)

                    for i in range(len(declared_list)):
                        self.append_stmts(statements, node, {"export_stmt": {"name": declared_list[i]}})
                else:
                    value = self.find_child_by_field(node, "value")

                    if value:
                        shadow_value = self.parse(value, statements)
                        self.append_stmts(statements, node, {"export_stmt": {"name": shadow_value, "attrs": ['default']}})

    def empty_statement(self, node: Node, statements: list):
        return ""





    def variable_declaration(self, node: Node, statements: list):
        attrs = []
        kind = self.find_child_by_field(node, "kind")
        if kind:
            shadow_kind = self.read_node_text(kind)
            attrs.append(shadow_kind)
        else:
            attrs.append("var")


        return_vals = []


        declarators = node.named_children
        for child in declarators:
            if self.is_comment(child):
                continue

            name = self.find_child_by_field(child, "name")
            value = self.find_child_by_field(child, "value")
            if name is None:
                continue

            shadow_value = self.parse(value, statements)
            if name.type == "identifier":
                shadow_name = self.read_node_text(name)
                return_vals.append(shadow_name)
                self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_name}})

                if shadow_value:
                    self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_name, "operand": shadow_value}})

            elif name.type == "array_pattern":
                index = 0

                previous_was_comma = False
                encountered_open_bracket = False

                for p in name.children:
                    if self.is_comment(p):
                        previous_was_comma = False
                        encountered_open_bracket = False
                        continue
                    elif p.type == "[" or p.type == "]":
                        previous_was_comma = False
                        encountered_open_bracket = True
                        continue
                    elif p.type == ",":
                        if previous_was_comma or encountered_open_bracket:
                            index += 1
                        previous_was_comma = True
                        encountered_open_bracket = False
                        continue
                    elif p.type == "rest_pattern":
                        previous_was_comma = False
                        encountered_open_bracket = False
                        name = p.named_children[-1]
                        shadow_name = self.parse(name, statements)
                        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_name}})
                        self.append_stmts(statements, node, {"assign": {"target": shadow_name, "operand": shadow_value}})
                    else:
                        previous_was_comma = False
                        encountered_open_bracket = False
                        elem = self.parse(p, statements)
                        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": elem}})
                        self.append_stmts(statements, node, {"array_read": {"target": elem, "array": shadow_value, "index": str(index)}})
                    index += 1

            elif name.type == "object_pattern":
                for p in name.named_children:
                    if self.is_comment(p):
                        continue

                    if p.type == "shorthand_property_identifier_pattern":

                        pattern = self.read_node_text(p)

                        return_vals.append(pattern)

                        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": pattern}})

                        if shadow_value:
                            self.append_stmts(statements, node, {"field_read": {"target": pattern, "receiver_object": shadow_value, "field": pattern}})

                    elif p.type == "pair_pattern":

                        left_child = self.find_child_by_field(p, "key")
                        right_child = self.find_child_by_field(p, "value")

                        shadow_left_child = self.property_name(left_child, statements)
                        shadow_right_child = self.parse(right_child, statements)

                        return_vals.append(shadow_right_child)

                        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_right_child}})

                        if shadow_value:
                            self.append_stmts(statements, node, {"field_read": {"target": shadow_right_child, "receiver_object": shadow_value, "field": shadow_left_child}})

                    elif p.type == "object_assignment_pattern":
                        left_child = self.find_child_by_field(p, "left")
                        right_child = self.find_child_by_field(p, "right")

                        shadow_left_child = self.read_node_text(left_child)
                        shadow_right_child = self.parse(right_child, statements)

                        return_vals.append(shadow_right_child)

                        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_left_child}})
                        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left_child, "operand": shadow_right_child}})

        return return_vals

    def read_node_pref_children(self, node, stop_char):
        prefix_children = []
        for child in node.children:
            if not util.isna(child):
                content = self.read_node_text(child)

                if content == stop_char:
                    break
                prefix_children.append(content)
        for item in ["function"]:
            while item in prefix_children:
                prefix_children.remove(item)
        return prefix_children

    def function_declaration(self, node: Node, statements: list, from_class_body = False):
        gir_node = {}


        gir_node["attrs"] = []

        shadow_children = self.read_node_pref_children(node, "(")
        if "async" in shadow_children:
            gir_node["attrs"].append("async")

        if "*" in shadow_children:
            gir_node["attrs"].append(LIAN_INTERNAL.GENERATOR_DECL)


        if "static" in shadow_children:
            gir_node["attrs"].append("static")
        if "get" in shadow_children:
            gir_node["attrs"].append("get")
        if "set" in shadow_children:
            gir_node["attrs"].append("set")


        name = self.find_child_by_field(node, "name")
        if not name:
            shadow_name = self.tmp_method()
        elif node.type == "method_definition":
            if from_class_body:
                shadow_name =  self.property_name(name, statements)

                if shadow_name.startswith("#"):
                    gir_node["attrs"].append("private")
                    shadow_name = shadow_name[1:]
            else:
                shadow_name = self.tmp_method()
        else:
            shadow_name = self.read_node_text(name)
        gir_node["name"] = shadow_name


        gir_node["parameters"] = []
        simple_param = self.find_child_by_field(node, "parameter")

        if simple_param:
            shadow_name = self.read_node_text(simple_param)
            gir_node["parameters"].append({"parameter_decl": {"attrs": [], "name": shadow_name}})

        else:
            parameters = self.find_child_by_field(node, "parameters")
            for child in parameters.named_children:
                if self.is_comment(child):
                    continue

                self.formal_parameter(child, gir_node["parameters"])


        gir_node["body"] = []
        body = self.find_child_by_field(node, "body")
        if (self.is_expression(body) or self.is_literal(body) or self.is_identifier(body)):

            shadow_expr = self.parse(body, gir_node["body"])
            gir_node["body"].append({"return_stmt": {"name": shadow_expr}})
        else:

            self.parse(body, gir_node["body"])

        self.append_stmts(statements, node, {"method_decl": gir_node})
        if (node.type == "function_declaration"
            or node.type == "generator_function_declaration"):
            return [shadow_name]
        else:
            return shadow_name

    def formal_parameter(self, node: Node, statements: list):
        attrs = []

        if node.type == "assignment_pattern":
            name = self.find_child_by_field(node, "left")
            value = self.find_child_by_field(node, "right")

            shadow_name = self.parse(name, statements)
            shadow_value = self.parse(value, statements)

            self.append_stmts(statements, node, {"parameter_decl": {"attrs": attrs, "name": shadow_name, "default_value": shadow_value}})

        elif node.type == "rest_pattern":
            attrs.append(LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER)
            name = node.named_children[-1]
            shadow_name = self.parse(name, statements)
            self.append_stmts(statements, node, {"parameter_decl": {"attrs": attrs, "name": shadow_name}})

        elif node.type == "array_pattern":
            tmp_arr = self.tmp_variable()
            my_arr = []
            index = 0

            previous_was_comma = False
            encountered_open_bracket = False

            for p in node.children:
                if self.is_comment(p):
                    previous_was_comma = False
                    encountered_open_bracket = False
                    continue
                elif p.type == "[" or p.type == "]":
                    previous_was_comma = False
                    encountered_open_bracket = True
                    continue
                elif p.type == ",":
                    if previous_was_comma or encountered_open_bracket:
                        my_arr.append(" ")
                        index += 1
                    previous_was_comma = True
                    encountered_open_bracket = False
                    continue
                else:
                    previous_was_comma = False
                    encountered_open_bracket = False
                    elem = self.parse(p, statements)
                    my_arr.append(elem)
                    self.append_stmts(statements, node, {"array_read": {"target": elem, "array": tmp_arr, "index": str(index)}})
                index += 1
                for elem in my_arr:
                    self.append_stmts(statements, node, {"parameter_decl": {"attrs": attrs, "name": elem}})

        elif node.type == "object_pattern":
            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"parameter_decl": {"attrs": attrs, "name": tmp_var}})
            for p in node.named_children:
                if self.is_comment(p):
                    continue

                if p.type == "shorthand_property_identifier_pattern":
                    pattern = self.read_node_text(p)
                    self.append_stmts(statements, node, {"field_read": {"receiver_object": tmp_var, "field": pattern, "target": pattern}})
                elif p.type == "pair_pattern":
                    left_child = self.find_child_by_field(p, "key")
                    right_child = self.find_child_by_field(p, "value")

                    shadow_left_child = self.property_name(left_child, statements)
                    shadow_right_child = self.parse(right_child, statements)
                    self.append_stmts(statements, node, {"field_read": {"receiver_object": tmp_var, "field": shadow_left_child, "target": shadow_right_child}})

        else:
            shadow_name = self.parse(node, statements)
            self.append_stmts(statements, node, {"parameter_decl": {"attrs": attrs, "name": shadow_name}})

    def class_declaration(self, node: Node, statements: list):
        gir_node = {}


        gir_node["attrs"] = ["class"]


        name = self.find_child_by_field(node, "name")
        if name:
            shadow_name = self.read_node_text(name)
        else:
            shadow_name = self.tmp_class()
        gir_node["name"] = shadow_name


        gir_node["type_parameters"] = []


        gir_node["supers"] = []
        class_heritage = self.find_child_by_type(node, "class_heritage")
        if class_heritage:
            expr = class_heritage.named_children[-1]
            shadow_expr = self.parse(expr, statements)
            gir_node["supers"].append(shadow_expr)


        body = self.find_child_by_field(node, "body")
        self.class_body(body, gir_node)

        self.append_stmts(statements, node, {"class_decl": gir_node})
        if node.type == "class":
            return shadow_name
        else:
            return [shadow_name]

    def class_body(self, node, gir_node):
        gir_node["fields"] = []
        gir_node["methods"] = []
        gir_node["nested"] = []
        init_class_method_body = []
        static_init_class_method_body = []


        field_defs = self.find_children_by_type(node, "field_definition")
        for field_def in field_defs:
            statements = []
            extra = init_class_method_body
            shadow_children = list(map(self.read_node_text, field_def.children))
            if "static" in shadow_children:
                extra = static_init_class_method_body

            self.field_definition(field_def, statements)

            if statements:
                for stmt in statements:
                    if "variable_decl" in stmt:
                        gir_node["fields"].append(stmt)
                    elif "constant_decl" in stmt:
                        gir_node["fields"].append(stmt)
                    else:
                        extra.append(stmt)


        static_blocks = self.find_children_by_type(node, "class_static_block")
        for static_block in static_blocks:
            self.parse(static_block, static_init_class_method_body)

        if init_class_method_body:
            gir_node["methods"].insert(0,
                {
                    "method_decl":{
                        "name": LIAN_INTERNAL.CLASS_INIT,
                        "body": init_class_method_body
                    }
                }
            )

        if static_init_class_method_body:
            gir_node["methods"].insert(0,
                {
                    "method_decl":{
                        "name": LIAN_INTERNAL.CLASS_STATIC_INIT,
                        "body": static_init_class_method_body
                    }
                }
            )


        method_defs = self.find_children_by_type(node, "method_definition")
        for method_def in method_defs:
            self.function_declaration(method_def, gir_node["methods"], True)

    def field_definition(self, node: Node, statements: list):
        attrs = []
        shadow_children = list(map(self.read_node_text, node.children))
        if "static" in shadow_children:
            attrs.append("static")

        prop_name = self.find_child_by_field(node, "property")
        shadow_name = self.property_name(prop_name, statements)

        init_value = self.find_child_by_field(node, "value")
        if init_value:
            shadow_value = self.parse(init_value, statements)
            self.append_stmts(statements, node, {"field_write": {"receiver_object": self.global_this(),
                                               "field": shadow_name, "source": shadow_value}})


        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_name}})

    def property_name(self, node: Node, statements: list):
        if (node.type == "property_identifier" or
                node.type == "private_property_identifier" or
                node.type == "computed_property_name"):
            shadow_name = self.read_node_text(node)
        else:
            shadow_name = self.parse(node, statements)

        return shadow_name

    def is_literal(self, node):
        return self.obtain_literal_handler(node) is not None

    def literal(self, node: Node, statements: list, replacement: list):
        handler = self.obtain_literal_handler(node)
        return handler(node, statements, replacement)

    def is_declaration(self, node):
        return self.check_declaration_handler(node) is not None

    def declaration(self, node: Node, statements: list):
        handler = self.check_declaration_handler(node)
        return handler(node, statements)

    def is_expression(self, node):
        return self.check_expression_handler(node) is not None

    def expression(self, node: Node, statements: list):
        handler = self.check_expression_handler(node)
        return handler(node, statements)

    def is_statement(self, node):
        return self.check_statement_handler(node) is not None

    def statement(self, node: Node, statements: list):
        handler = self.check_statement_handler(node)
        return handler(node, statements)
