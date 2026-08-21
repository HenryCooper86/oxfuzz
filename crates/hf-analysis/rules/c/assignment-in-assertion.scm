; CWE-754: Improper Check for Unusual or Exceptional Conditions
; SEI CERT C EXP45-C: an assignment inside assert assigns rather than compares,
; and because assert compiles away under NDEBUG the assignment disappears in a
; release build, so debug and release diverge.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list (assignment_expression))
  (#match? @fn "^(assert|_assert)$")) @hit
