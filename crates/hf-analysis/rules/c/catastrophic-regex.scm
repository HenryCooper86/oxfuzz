; CWE-1333: Inefficient Regular Expression Complexity
; A nested quantifier makes backtracking exponential in the input length, so a
; short attacker-chosen subject hangs the process.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list (string_literal) @pattern)
  (#match? @fn "^(regcomp|regexec)$")
  (#match? @pattern "\\([^)]*[+*]\\)[+*]")) @hit
