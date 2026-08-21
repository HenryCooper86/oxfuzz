; CWE-209: Generation of Error Message Containing Sensitive Information
; Printing a pointer with %p discloses a live address, which defeats ASLR for
; anyone who can read the output.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list (string_literal) @fmt)
  (#match? @fn "^(printf|fprintf|sprintf|snprintf|syslog)$")
  (#match? @fmt "%p")) @hit
