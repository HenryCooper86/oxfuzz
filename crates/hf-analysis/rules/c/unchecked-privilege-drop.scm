; CWE-252: Unchecked Return Value
; SEI CERT C POS37-C: setuid and friends can fail, and a program that assumes
; the drop succeeded continues running with the privileges it believed it had
; given up.
(expression_statement
  (call_expression
    function: (identifier) @fn
    (#match? @fn "^(setuid|seteuid|setgid|setegid|setreuid|setregid)$")) @hit)
