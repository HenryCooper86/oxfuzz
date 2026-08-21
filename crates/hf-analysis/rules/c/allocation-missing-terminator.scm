; CWE-193: Off-by-one Error
; SEI CERT C STR31-C: strlen does not count the terminating NUL, so allocating
; exactly strlen bytes leaves no room for it and the copy that follows writes
; one byte past the end.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    .
    (call_expression function: (identifier) @len)
    .)
  (#match? @fn "^(malloc|alloca|valloc)$")
  (#eq? @len "strlen")) @hit
