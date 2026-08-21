; CWE-480: Use of Incorrect Operator
; SEI CERT C EXP45-C: an assignment where a comparison was meant yields the
; assigned value as the condition, so the branch is taken on the value rather
; than on the intended equality.
[
  (if_statement condition: (parenthesized_expression (assignment_expression)))
  (while_statement condition: (parenthesized_expression (assignment_expression)))
] @hit
