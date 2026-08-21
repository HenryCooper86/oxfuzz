; CWE-787: Out-of-bounds Write
; SEI CERT C STR31-C: strncat's third argument is the space remaining after the
; existing contents, not the size of the destination. A constant cannot express
; that, so it overflows once the destination is already partly full.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list . (_) (_) (number_literal) .)
  (#eq? @fn "strncat")) @hit
