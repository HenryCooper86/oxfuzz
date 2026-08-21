; CWE-676: Use of Potentially Dangerous Function
; SEI CERT C STR31-C: a %s or %[ conversion without a field width writes an
; unbounded run of input into the destination. Matched on the literal because
; the width is part of the format string, not of the call shape.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list (string_literal) @fmt)
  (#match? @fn "^(scanf|fscanf|sscanf|vscanf|vfscanf|vsscanf)$")
  (#match? @fmt "%[*]?(s|\\[)")) @hit
