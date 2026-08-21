; CWE-193: Off-by-one Error
; SEI CERT C ARR30-C: a loop bounded by `<=` against a count runs one iteration
; past the last valid index, so the final subscript is out of range.
(for_statement
  condition: (binary_expression
    operator: "<="
    right: (call_expression function: (identifier) @len))
  (#match? @len "^(strlen|sizeof|count|length)$")) @hit
