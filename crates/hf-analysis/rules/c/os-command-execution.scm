; CWE-78: OS Command Injection
; SEI CERT C ENV33-C: system and popen hand their argument to a shell, so any
; caller-chosen input reaching the string is interpreted as shell syntax rather
; than as data.
;
; Restricted to a caller-chosen argument. The same call on a local constant is
; not injectable, and reporting it would fire on correct code.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list . (identifier) @var)
  (#match? @fn "^(system|popen|execl|execlp|execle|execv|execvp|execvpe)$")) @hit
