; CWE-193: Off-by-one Error
; SEI CERT C ARR30-C: an array of n elements has no element n. Subscripting
; with the buffer's own size, or with a length used as if it were the last
; index, writes one past the end.
[
  (subscript_expression
    argument: (identifier) @buf
    index: (sizeof_expression value: (parenthesized_expression (identifier) @size))
    (#eq? @buf @size))
  (subscript_expression
    index: (binary_expression
      left: (call_expression function: (identifier) @len)
      operator: "-")
    (#eq? @len "strlen"))
] @hit
