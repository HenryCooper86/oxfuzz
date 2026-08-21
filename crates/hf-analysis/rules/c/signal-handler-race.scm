; CWE-364: Signal Handler Race Condition
; SEI CERT C SIG31-C and SIG34-C: signal() gives no control over blocked
; signals during handler execution and re-entry, so a handler installed this
; way races with itself and with the interrupted code.
(call_expression
  function: (identifier) @fn
  (#eq? @fn "signal")) @hit
