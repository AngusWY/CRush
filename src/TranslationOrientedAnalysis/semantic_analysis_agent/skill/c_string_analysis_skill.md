# C String Boundary Analysis Skill

Use this skill only when a requested field is `string_semantics`,
`c_string_read`, or `c_string_termination`. Recover C string boundary behavior;
do not prescribe a Rust representation.

## Evidence workflow

1. Do not classify a pointer as a string from `char *` alone.
2. Require positive evidence: string-literal origin, explicit `\0` tests or
   writes, known string APIs such as `strlen` and `strcmp`, or data flow from a
   confirmed string pointer.
3. For a function parameter, inspect callers and the corresponding actual
   argument. For a caller argument, inspect how the callee uses the matching
   parameter. Use `get_callers` and `get_callee_parameter_usage` when needed.
4. Preserve short-circuit evaluation. A UTF-8 lookahead can safely encounter
   the one readable C terminator and stop; this does not make bytes after that
   terminator readable.
5. Distinguish a logical C string from a binary buffer containing zero bytes.
   If raw byte operations make the backing layout observable, do not assume a
   payload-only representation.

## Pointer output

For a confirmed NUL-terminated byte string, fill `string_semantics` exactly as:

```json
{
  "kind": "nul_terminated_bytes",
  "payload_excludes_terminator": true,
  "terminator_readable_in_c": true
}
```

Leave the field unresolved when there is no positive string evidence.

## Read output

For a read that relies on the terminator, fill `c_string_read` with:

```json
{
  "buffer": "str",
  "access_index": "offset + 1",
  "role": "lookahead",
  "logical_end_value": 0
}
```

Allowed roles are:

- `terminator_test` for an explicit end-of-string test;
- `lookahead` for a subsequent-byte read whose validation stops at the
  terminator;
- `end_boundary_probe` for dereferencing the logical end pointer.

Do not model a general out-of-bounds read as zero.

## Write output

`c_string_termination` records the C buffer, terminator index, `index + 1`
minimum C capacity, and zero-valued write. It does not require a native Rust
payload representation to store a physical zero unless raw layout remains
observable or an external C API requires it.
