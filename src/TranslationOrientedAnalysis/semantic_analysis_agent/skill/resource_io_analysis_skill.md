# Stateful I/O Resource Analysis Skill

Use this skill when a declaration has `resource_required: true`. The supported
resource is a C stdio handle rooted in opaque `FILE` or `_IO_FILE`. Analyze its
observable protocol; never infer the private C library layout or prescribe a
Rust representation.

## Evidence workflow

1. Preserve exact pointer indirection. `FILE *` is a direct handle. Classify
   `FILE **` as `sequence` only when indexed elements and a count are evident,
   as `slot` when `*out` is assigned, and otherwise as `unknown`.
2. Record outer pointer ownership separately from ownership/nullability of the
   stream handle stored in a multi-level declaration.
3. Treat `stdin`, `stdout`, and `stderr` as borrowed static process resources;
   treat successful `fopen` results as owned; retain `fclose` as consumption
   evidence.
4. Record every relevant operation, its target expression, evidence site,
   origin (`direct`, `callee`, or `caller`), and non-empty cross-call path.
5. Include `fopen`, `fclose`, `fgetc`, `getc`, `ungetc`, `fread`, `fwrite`,
   `feof`, `ferror`, `clearerr`, `fseek`, `fseeko`, `ftell`, `ftello`,
   `rewind`, and `fflush` when present.
6. Preserve programmatic flow edges and `protocol_id`. Add evidence or fill
   unresolved handle fields, but do not discard direct or propagated facts.
7. Record the observable state requirements implied by the complete protocol.
   If evidence is insufficient, retain the field in `unresolved_fields`.

## Output contract

Fill `resource_semantics` with a version 4 obligation object such as:

```json
{
  "resource_kind": "file_stream",
  "resource_identity": "fin",
  "protocol_id": "stdio-flow-2241-3640",
  "handle": {
    "indirection": 1,
    "role": "direct",
    "element_ownership": "borrowed",
    "element_nullability": "nonnull"
  },
  "capabilities": ["read"],
  "operations": [
    {
      "callee": "fgetc",
      "effect": "read_bytes_and_advance_cursor",
      "origin": "direct",
      "target": "fin",
      "site": "fgetc(fin)"
    },
    {
      "callee": "feof",
      "effect": "test_eof_state",
      "origin": "caller",
      "target": "fid",
      "site": "feof(fid)",
      "call_path": ["get_counts:get_word(fid)"]
    }
  ],
  "flow_edges": [
    {
      "kind": "call_argument",
      "source": "decl:2241",
      "target": "decl:3640",
      "site": "get_counts:get_word(fid)"
    }
  ],
  "state_requirements": [
    "eof_is_sticky_after_failed_read",
    "eof_survives_function_return"
  ],
  "unresolved_fields": ["creation_site", "open_mode", "end_site"]
}
```

Allowed operation effects additionally include `push_back_byte` and
`clear_eof_and_error_state`. Allowed flow kinds are `call_argument`,
`return_assignment`, `alias`, `stored`, and `indexed_element`.

Never emit `rust_representation` or `stateful_across_calls`. Do not name
`std::fs::File`, an adapter, an enum, or any other Rust implementation choice.
