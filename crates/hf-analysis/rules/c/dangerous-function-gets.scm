; CWE-242: Use of Inherently Dangerous Function
; SEI CERT C STR31-C: gets() has no bound parameter and cannot be called safely
; for any input, so any call site is a finding regardless of surrounding context.
(call_expression
  function: (identifier) @fn
  (#eq? @fn "gets")) @hit
