; CWE-806: Buffer Access Using Size of Source Buffer
; SEI CERT C ARR38-C: snprintf's second argument bounds the write, so it must
; describe the destination. Passing sizeof of anything else bounds the copy by
; a size unrelated to the space available.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    .
    (identifier) @dst
    (sizeof_expression value: (parenthesized_expression (identifier) @size)))
  (#match? @fn "^(snprintf|vsnprintf)$")
  (#not-eq? @dst @size)) @hit
