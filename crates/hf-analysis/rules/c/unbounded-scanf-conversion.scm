; CWE-676: Use of Potentially Dangerous Function
; SEI CERT C STR31-C: a %s or %[ conversion without a field width writes an
; unbounded run of input into the destination.
;
; scanf and vscanf read standard input, which is always caller-chosen, so no
; further check is needed. The string-scanning variants take a source argument
; and are handled by unbounded-string-scan, which requires that source to be
; caller-chosen rather than a literal.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list . (string_literal) @fmt)
  (#match? @fn "^(scanf|vscanf)$")
  (#match? @fmt "%[*]?(s|\\[)")) @hit
