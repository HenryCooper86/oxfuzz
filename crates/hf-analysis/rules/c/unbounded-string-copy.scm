; CWE-676: Use of Potentially Dangerous Function
; SEI CERT C STR31-C: strcpy, strcat, sprintf, and vsprintf write until a NUL
; is reached, so the destination size never constrains the write and the only
; bound is the input.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat)$")) @hit
