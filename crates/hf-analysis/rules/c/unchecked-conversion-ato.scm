; CWE-252: Unchecked Return Value
; SEI CERT C ERR34-C: the ato* family cannot distinguish a successfully
; converted zero from a parse failure, so a caller has no way to detect
; malformed input at all.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^ato(i|l|ll)$")) @hit
