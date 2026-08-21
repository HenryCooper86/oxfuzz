; CWE-676: Use of Potentially Dangerous Function
; SEI CERT C STR31-C: strcpy and strcat write until a NUL is reached, so the
; destination size never constrains the write and the only bound is the input.
;
; sprintf is not here: whether it is bounded depends on its conversions, which
; unbounded-format-write decides from the format literal.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(strcpy|strcat|wcscpy|wcscat)$")) @hit
