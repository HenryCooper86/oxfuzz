; CWE-190: Integer Overflow or Wraparound
; SEI CERT C INT30-C and MEM07-C: a product of two attacker-influenced counts
; wraps silently in size_t, so the allocation succeeds at a fraction of the
; intended size and every subsequent write overflows it. calloc exists for this
; case because it checks the multiplication.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list . (binary_expression operator: "*") @hit .)
  (#match? @fn "^(malloc|alloca|realloc)$"))
