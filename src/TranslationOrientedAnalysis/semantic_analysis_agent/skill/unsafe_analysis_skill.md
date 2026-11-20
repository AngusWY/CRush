# Unsafe Stmt Analysis Skill

This skill explains how to fill missing semantic hints for unsafe-related C
statements. Use only the sections that match the current task operations.

General rules:

- Use the current entity source as the primary evidence.
- Use existing `current_semantics` as programmatic evidence, not as final truth.
- Fill only fields listed in `missing_fields`.
- If the evidence is insufficient, leave the field unresolved.
- Prefer C-level expressions such as `buf[i]`, `msg->buf`, `*p`, or `p + off`
  over GIR temporary names.
- Do not invent aliases, lifetimes, or ownership transfers without source
  evidence.

## array_read

Use this section for `array_read`.

Relevant fields:

- `array_role`: where the array/buffer comes from. Use values such as
  `parameter_array`, `local_array`, `global_array`, or `alias`.
- `resolves_to_element`: the concrete C element being read.

Analysis steps:

1. Identify the array expression and index expression in the statement.
2. If the statement is directly `array[index]`, set `resolves_to_element` to
   that expression.
3. If the array expression is an alias, trace the alias in the current entity
   source and recover the original base plus offset when possible.
4. Set `array_role` from the source of the base array:
   parameter -> `parameter_array`, local array -> `local_array`, global array ->
   `global_array`, traced alias -> `alias`.
5. If the base or index cannot be resolved from the provided source, leave the
   field unresolved.

Example:

```c
x = buf[i];
```

Expected updates:

```json
{"resolves_to_element": "buf[i]", "array_role": "parameter_array"}
```

## array_write

Use this section for `array_write`.

Relevant fields:

- `array_role`: where the written array/buffer comes from.
- `resolves_to_element`: the concrete C element being written.
- `write_source_deps`: symbols or expressions used to compute the value being
  written.
- `c_string_termination`: the capacity and write contract established by an
  explicit C NUL terminator.

Analysis steps:

1. Identify the left-hand array expression and index.
2. Set `resolves_to_element` to the C-level write target, usually
   `array[index]`.
3. Determine `array_role` the same way as `array_read`.
4. For `write_source_deps`, list the right-hand value dependencies, not the
   destination. Include variables, field reads, array reads, or expressions that
   compute the stored value.
5. Do not include the written target itself as a dependency unless it is also
   read by the right-hand expression.
6. If the right-hand side is `\0`, a NUL character literal, or a value that can
   be traced unambiguously to one, fill `c_string_termination` when that field
   is requested. Set `buffer` to the resolved base buffer, `terminator_index`
   to the exact C index expression, `minimum_capacity` to `(index) + 1`,
   `write_target` to the resolved element, `terminator_value` to `0`, and
   `capacity_includes_terminator` to `true`.
7. Do not infer this contract merely because the element type is `char` or the
   buffer is later used as bytes. If the zero-valued origin is ambiguous, leave
   the field unresolved.

Example:

```c
buf[i] = value + 1;
```

Expected updates:

```json
{"resolves_to_element": "buf[i]", "write_source_deps": ["value"]}
```

For a terminator write:

```c
buf[len] = '\0';
```

Expected `c_string_termination` update:

```json
{
  "buffer": "buf",
  "terminator_index": "len",
  "minimum_capacity": "(len) + 1",
  "write_target": "buf[len]",
  "terminator_value": 0,
  "capacity_includes_terminator": true
}
```

## mem_read

Use this section for `mem_read`.

Relevant fields:

- `array_role`: source category of the memory being read when the address
  resolves to an array/buffer element.
- `resolves_to_element`: concrete object or element read through the pointer.
- `address_origin_expr`: expression that produced the address being read.

Analysis steps:

1. Identify the pointer/address expression being dereferenced.
2. If it is a direct dereference such as `*p`, trace `p` within the current
   entity source.
3. If `p` comes from `arr + i`, `&arr[i]`, or an array alias, recover the
   concrete element expression.
4. If it comes from a field or address-of expression, set `address_origin_expr`
   to that source expression.
5. If the pointer cannot be traced with the provided source, leave unresolved.

## mem_write

Use this section for `mem_write`.

Relevant fields:

- `array_role`: source category of the memory being written when applicable.
- `resolves_to_element`: concrete object or element written through the pointer.
- `address_origin_expr`: expression that produced the address being written.
- `write_source_deps`: symbols or expressions used to compute the stored value.

Analysis steps:

1. Identify the pointer/address expression being written through.
2. Trace the address source as in `mem_read`.
3. Set `resolves_to_element` to the C-level target if it can be recovered.
4. For `write_source_deps`, list dependencies of the value stored through the
   pointer, not the destination pointer itself.
5. If the address or source value cannot be resolved, leave only those fields
   unresolved.

Example:

```c
*p = x;
```

If `p` cannot be traced:

```json
{"write_source_deps": ["x"]}
```

and leave `resolves_to_element` unresolved.

## addr_of

Use this section for `addr_of`.

Relevant fields:

- `source_element`: the C expression whose address is taken.
- `escape`: how the produced address escapes the local statement.

Analysis steps:

1. Identify the expression passed to `&`.
2. Set `source_element` to that expression, such as `x`, `arr[i]`, or
   `msg->buf`.
3. Inspect later uses of the produced pointer in the current entity.
4. Add `escape` entries for clear escapes: returned, stored into a field/global,
   or passed to a function that may store or return it.
5. If the address is only used locally and does not escape, leave `escape`
   unresolved unless the field is requested and evidence is clear.

## field_read

Use this section for `field_read`.

Relevant fields:

- `is_pointer_field`: whether the field itself is pointer-typed or is used as a
  pointer value.

Analysis steps:

1. Identify the accessed field expression, such as `obj->field` or `obj.field`.
2. Check the struct/union definition in the provided source when available.
3. Set `is_pointer_field` to true only when the field type is a pointer or the
   field value is used as a pointer.
4. If the type definition is not available and usage is ambiguous, leave the
   field unresolved.

## field_write

Use this section for `field_write`.

Relevant fields:

- `is_pointer_field`: whether the written field itself is pointer-typed.
- `establishes_alias`: whether storing the value into the field creates a
  pointer/array alias that can be used later.
- `write_source_deps`: symbols or expressions used to compute the stored value.

Analysis steps:

1. Identify the field being written and the source value.
2. Determine whether the field is pointer-typed from the struct/union
   definition or source usage.
3. Set `establishes_alias` to true if a pointer, array, field pointer, or
   address expression is stored into the field.
4. Set `establishes_alias` to false only when the source is clearly a scalar or
   non-pointer value.
5. For `write_source_deps`, list the source value dependencies.

## type_cast_stmt

Use this section for `type_cast_stmt`.

Relevant fields:

- `cast_kind`: semantic category of the cast.
- `offset_base`: base object if the cast is connected to pointer offset logic.
- `offset`: offset expression associated with the cast or pointer arithmetic.
- `constraints`: translation or safety constraints implied by the cast.

Analysis steps:

1. Compare the source type and target type.
2. Classify obvious casts:
   pointer to pointer -> `pointer_to_pointer`, pointer to integer ->
   `pointer_to_integer`, integer to pointer -> `integer_to_pointer`, qualifier
   only -> `qualifier_change`.
3. If the cast is part of pointer arithmetic, identify the base and offset.
4. Add constraints for unsafe reinterpretation, lost constness, integer-pointer
   conversion, or alignment-sensitive casts.
5. If source and target types are not visible, leave `cast_kind` unresolved.

## return_stmt

Use this section for `return_stmt`.

Relevant fields:

- `return_kind`: whether the returned value is owned, borrowed, null, borrowed
  from parameter/global/field, or a local-address risk.
- `transfer_kind`: whether ownership is returned, a borrow is returned, or no
  ownership transfer occurs.
- `lifetime_source`: source object that determines the returned borrowed
  pointer's lifetime.
- `return_local_addr_risk`: true when returning address of local storage.

Analysis steps:

1. Identify the returned expression.
2. If it is `NULL` or `0`, use return kind `null` and no ownership transfer.
3. If it returns a value created by allocation and not freed before return, use
   owned return semantics.
4. If it returns a parameter or a value derived from a parameter, use borrowed
   return semantics and set `lifetime_source` to that parameter.
5. If it returns a global or static object, mark it as borrowed from global.
6. If it returns the address of a local variable or stack object, set
   `return_local_addr_risk` to true and use local-address-risk semantics.
7. If the origin cannot be determined from the source, leave the relevant fields
   unresolved.
