; CWE-131: Incorrect Calculation of Buffer Size
; SEI CERT C STR31-C: snprintf, strlcpy, and strlcat return the length they
; would have written, not the length they wrote. Discarding it hides truncation,
; and later code then treats a truncated string as complete.
(expression_statement
  (call_expression
    function: (identifier) @fn
    (#match? @fn "^(snprintf|vsnprintf|strlcpy|strlcat)$")) @hit)
