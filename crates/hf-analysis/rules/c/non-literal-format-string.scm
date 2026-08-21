; CWE-134: Use of Externally-Controlled Format String
; SEI CERT C FIO30-C: when the format argument is not a literal, an attacker
; who controls it controls the conversions, and %n turns that into an arbitrary
; write.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list . (identifier) @fmt)
  (#match? @fn "^(printf|vprintf|scanf|vscanf)$")) @hit
