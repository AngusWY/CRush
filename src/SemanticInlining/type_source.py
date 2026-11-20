from __future__ import annotations

from functools import lru_cache

from .models import EntityMetadata


@lru_cache(maxsize=1)
def _c_parser():
    import tree_sitter_c
    from tree_sitter import Language, Parser

    binding = tree_sitter_c.language()
    try:
        return Parser(Language(binding))
    except TypeError:
        from pathlib import Path

        language = Language(
            str(Path(tree_sitter_c.__file__).parent / "_binding.abi3.so"), "c"
        )
        parser = Parser()
        parser.set_language(language)
        return parser


def isolate_type_source(
    source: str, entity: EntityMetadata, *, original_coordinates: bool = False
) -> str:

    if entity.kind != "type":
        return source

    encoded = source.encode("utf-8")
    root = _c_parser().parse(encoded).root_node
    candidates = []
    named_candidates = []
    specifiers = {"struct_specifier", "union_specifier", "enum_specifier"}

    def visit(node):
        if node.type == "type_definition":
            declarator = node.child_by_field_name("declarator")
            if declarator is not None:

                names = []
                pending = [declarator]
                while pending:
                    child = pending.pop()
                    if child.type == "type_identifier":
                        names.append(encoded[child.start_byte:child.end_byte].decode("utf-8"))
                    pending.extend(child.named_children)
                if entity.name in names:
                    named_candidates.append(node)
                    return
        if node.type in specifiers and node.child_by_field_name("body") is not None:
            candidates.append(node)
            name = node.child_by_field_name("name")
            if name is not None and encoded[name.start_byte:name.end_byte].decode("utf-8") == entity.name:
                named_candidates.append(node)

            return
        for child in node.named_children:
            visit(child)

    visit(root)
    selected = None
    if original_coordinates:
        matches = [
            node for node in candidates + named_candidates
            if tuple(node.start_point) == (0, entity.source.start_col)
            and tuple(node.end_point) == (
                entity.source.end_line - entity.source.start_line,
                entity.source.end_col,
            )
        ]
        if matches:
            selected = matches[0]
    if selected is None:

        choices = named_candidates or candidates
        unique = {(node.start_byte, node.end_byte): node for node in choices}
        if len(unique) > 1:
            raise ValueError(f"ambiguous type source for entity {entity.entity_id} ({entity.name})")
        if not unique:
            return source
        selected = next(iter(unique.values()))


    prefix = encoded[:selected.start_byte].decode("utf-8")
    suffix = encoded[selected.end_byte:].decode("utf-8")
    blank = lambda text: "".join(char if char in "\r\n" else " " for char in text)
    definition = encoded[selected.start_byte:selected.end_byte].decode("utf-8")
    if not definition.rstrip().endswith(";"):
        definition += ";"
    return blank(prefix) + definition + blank(suffix)
