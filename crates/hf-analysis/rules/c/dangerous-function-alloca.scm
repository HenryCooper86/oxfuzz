; CWE-676: Use of Potentially Dangerous Function
; SEI CERT C MEM05-C: alloca grows the stack by an amount the caller computes,
; so an attacker-influenced size moves the stack pointer out of the guard page
; and there is no failure return to check.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(alloca|_alloca|__builtin_alloca)$")) @hit
