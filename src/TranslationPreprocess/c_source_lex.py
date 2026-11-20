from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CCommentSpan:


    start: int
    end: int
    start_line: int
    end_line: int
    style: str
    text: str


def scan_c_comments(source: str) -> tuple[CCommentSpan, ...]:


    spans: list[CCommentSpan] = []
    index = 0
    line = 1
    length = len(source)
    state = "code"

    while index < length:
        char = source[index]
        following = source[index + 1] if index + 1 < length else ""

        if state == "code":
            if char == '"':
                state = "string"
                index += 1
                continue
            if char == "'":
                state = "char"
                index += 1
                continue
            if char == "/" and following == "/":
                start = index
                start_line = line
                index += 2
                while index < length and source[index] not in "\r\n":
                    index += 1
                spans.append(
                    CCommentSpan(
                        start=start,
                        end=index,
                        start_line=start_line,
                        end_line=line,
                        style="line",
                        text=source[start:index],
                    )
                )
                continue
            if char == "/" and following == "*":
                start = index
                start_line = line
                index += 2
                while index < length:
                    if source[index] == "\n":
                        line += 1
                    if (
                        source[index] == "*"
                        and index + 1 < length
                        and source[index + 1] == "/"
                    ):
                        index += 2
                        break
                    index += 1
                spans.append(
                    CCommentSpan(
                        start=start,
                        end=index,
                        start_line=start_line,
                        end_line=line,
                        style="block",
                        text=source[start:index],
                    )
                )
                continue
            if char == "\n":
                line += 1
            index += 1
            continue

        if char == "\\":
            if following == "\r" and index + 2 < length and source[index + 2] == "\n":
                line += 1
                index += 3
            elif following == "\n":
                line += 1
                index += 2
            else:
                index += min(2, length - index)
            continue
        if (state == "string" and char == '"') or (
            state == "char" and char == "'"
        ):
            state = "code"
        if char == "\n":
            line += 1
        index += 1

    return tuple(spans)


def mask_c_non_code(source: str, *, mask_literals: bool) -> str:


    result = list(source)
    comment_spans = scan_c_comments(source)
    for span in comment_spans:
        _mask_range(result, source, span.start, span.end)

    if mask_literals:
        _mask_literals(result, source, comment_spans)
    return "".join(result)


def comment_start_columns(source: str) -> dict[int, int]:


    starts: dict[int, int] = {}
    for span in scan_c_comments(source):
        line_start = source.rfind("\n", 0, span.start) + 1
        line_index = span.start_line - 1
        column = span.start - line_start
        starts[line_index] = min(starts.get(line_index, column), column)
    return starts


def _mask_range(result: list[str], source: str, start: int, end: int) -> None:
    for index in range(start, min(end, len(result))):
        if source[index] not in "\r\n":
            result[index] = " "


def _mask_literals(
    result: list[str],
    source: str,
    comment_spans: tuple[CCommentSpan, ...],
) -> None:
    index = 0
    comment_index = 0
    length = len(source)
    while index < length:
        if comment_index < len(comment_spans):
            comment = comment_spans[comment_index]
            if index >= comment.end:
                comment_index += 1
                continue
            if comment.start <= index < comment.end:
                index = comment.end
                comment_index += 1
                continue
        char = source[index]
        if char not in {'"', "'"}:
            index += 1
            continue
        quote = char
        start = index
        index += 1
        while index < length:
            if source[index] == "\\":
                index += min(2, length - index)
                continue
            if source[index] == quote:
                index += 1
                break
            index += 1
        _mask_range(result, source, start, index)
