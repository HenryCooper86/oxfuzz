; CWE-193: Off-by-one Error
; SEI CERT C STR31-C: a string of exactly sizeof(dst) characters still needs a
; terminator, so the guard must reject equality too. Comparing with > rather
; than >= lets the boundary case through.
(binary_expression
  left: (call_expression function: (identifier) @len)
  operator: ">"
  right: (sizeof_expression)
  (#eq? @len "strlen")) @hit
