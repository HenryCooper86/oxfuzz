; CWE-170: Improper Null Termination
; SEI CERT C STR32-C: strncpy writes exactly n bytes and adds no terminator
; when the source is at least that long. Bounding by the full destination size
; leaves no room for one, so every later string operation reads past the end.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    .
    (identifier) @dst
    (identifier)
    (sizeof_expression value: (parenthesized_expression (identifier) @size))
    .)
  (#eq? @fn "strncpy")
  (#eq? @dst @size)) @hit
