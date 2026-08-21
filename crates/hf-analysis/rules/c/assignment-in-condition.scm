; CWE-480: Use of Incorrect Operator
; SEI CERT C EXP45-C: an assignment where a comparison was meant yields the
; assigned value as the condition, so the branch is taken on the value rather
; than on the intended equality. The reverse confusion in a for-initializer
; discards the intended initialization, and `= +` is a transposed `+=`.
;
; An assignment deliberately compared -- `if ((p = f()) != NULL)` -- is not
; matched, because its condition is the comparison rather than the assignment.
[
  (if_statement condition: (parenthesized_expression (assignment_expression)))
  (while_statement condition: (parenthesized_expression (assignment_expression)))
  (for_statement initializer: (binary_expression operator: "=="))
  (assignment_expression right: (unary_expression operator: "+"))
] @hit
