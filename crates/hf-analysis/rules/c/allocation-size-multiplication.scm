; CWE-190: Integer Overflow or Wraparound
; SEI CERT C INT30-C and MEM07-C: size_t arithmetic wraps silently, so an
; allocation whose size is computed from attacker-influenced values can succeed
; at a fraction of the intended size, after which every write overflows it.
; calloc exists because it checks its own multiplication.
;
; Any arithmetic in any argument counts, not only a product as the sole
; argument: realloc(p, n * sizeof(T)) and calloc(n + 1, size) wrap exactly the
; same way. The call is reported rather than the expression, because a call
; spanning several lines is attributed to the line it starts on.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    (binary_expression operator: ["*" "+" "<<"]))
  (#match? @fn "^(malloc|calloc|realloc|reallocarray|alloca|valloc)$")) @hit
