; CWE-469: Use of Pointer Subtraction to Determine Size
; SEI CERT C ARR36-C: subtracting pointers into different objects is undefined,
; and the result is a signed ptrdiff_t that becomes a huge size_t when negative.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    (binary_expression
      left: (identifier)
      operator: "-"
      right: (identifier)) @hit)
  (#match? @fn "^(malloc|memcpy|memmove|memset|strncpy|strncat)$"))
