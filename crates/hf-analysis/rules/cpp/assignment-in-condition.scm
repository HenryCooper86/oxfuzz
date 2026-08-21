; CWE-480: Use of Incorrect Operator
; SEI CERT C EXP45-C: an assignment where a comparison was meant yields the
; assigned value as the condition, so the branch is taken on the value rather
; than on the intended equality.
;
; C++ wraps a condition in `condition_clause` rather than
; `parenthesized_expression`, because it also admits an init-statement, so the
; C form of this rule does not compile against this grammar.
[
  (if_statement condition: (condition_clause value: (assignment_expression)))
  (while_statement condition: (condition_clause value: (assignment_expression)))
] @hit
