; CWE-676: Use of Potentially Dangerous Function
; SEI CERT C FIO47-C: sprintf writes as many bytes as its conversions produce.
; A %s or %[ conversion is unbounded, so the destination overflows for a long
; enough argument; a width-bounded or numeric conversion cannot.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list (string_literal) @fmt)
  (#match? @fn "^(sprintf|vsprintf)$")
  (#match? @fmt "%[^%diouxXeEfgGcp]*(s|\\[)")) @hit
