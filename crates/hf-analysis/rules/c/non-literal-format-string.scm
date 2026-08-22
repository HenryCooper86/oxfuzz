; CWE-134: Use of Externally-Controlled Format String
; SEI CERT C FIO30-C: when the format is not a literal, whoever controls it
; controls the conversions, and %n turns that into an arbitrary write.
;
; One pattern per signature, because the format sits at a different position in
; each. Every child is anchored with `.` so the positions are consecutive:
; without the anchors a wildcard skips over a literal format and matches a data
; argument further along, which reports correct code.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list . [(identifier) (subscript_expression)] @fmt)
  (#match? @fn "^(printf|vprintf|scanf|vscanf)$")) @hit

(call_expression
  function: (identifier) @fn
  arguments: (argument_list . (_) . [(identifier) (subscript_expression)] @fmt)
  (#match? @fn "^(fprintf|vfprintf|dprintf|syslog|sscanf|fscanf)$")) @hit

(call_expression
  function: (identifier) @fn
  arguments: (argument_list . (_) . (_) . [(identifier) (subscript_expression)] @fmt)
  (#match? @fn "^(snprintf|vsnprintf)$")) @hit
