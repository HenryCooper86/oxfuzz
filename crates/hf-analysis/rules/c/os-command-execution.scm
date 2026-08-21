; CWE-78: OS Command Injection
; SEI CERT C ENV33-C: system and popen hand their argument to a shell, so any
; input reaching the string is interpreted as shell syntax rather than data.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(system|popen|execl|execlp|execle|execv|execvp|execvpe)$")) @hit
