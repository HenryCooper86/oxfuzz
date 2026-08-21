; CWE-676: Use of Potentially Dangerous Function
; SEI CERT C STR31-C: an unbounded %s conversion overflows the destination when
; the scanned source is longer than it.
;
; Restricted to a caller-chosen source: scanning a string literal cannot
; overflow anything, and the corpus marks those as acceptable.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list . (identifier) @var (string_literal) @fmt)
  (#match? @fn "^(sscanf|vsscanf|fscanf|vfscanf)$")
  (#match? @fmt "%[*]?(s|\\[)")) @hit
