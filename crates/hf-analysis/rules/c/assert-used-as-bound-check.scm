; CWE-754: Improper Check for Unusual or Exceptional Conditions
; SEI CERT C EXP31-C and MSC11-C: assert compiles away under NDEBUG, so a bound
; enforced only by an assert is not enforced in a release build. A relational
; comparison against a size or a length is validation; an equality check on an
; invariant is not, and the corpus accepts those.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    (binary_expression operator: ["<" "<=" ">" ">="]))
  (#match? @fn "^(assert|_assert|__ASSERT|__ASSERT_NO_MSG)$")) @hit
