; CWE-367: Time-of-check Time-of-use Race Condition
; SEI CERT C FIO01-C: access and stat answer a question about a path, not about
; a file, so the answer is stale the moment it returns and the path can be
; replaced before it is used.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(access|stat|lstat|faccessat)$")) @hit
