; CWE-190: Integer Overflow or Wraparound
; SEI CERT C INT30-C: size_t addition wraps silently. A single strlen plus a
; constant cannot wrap in practice -- the string would have to span the address
; space -- but summing two lengths can, and the result is then used as an
; allocation size followed by copies that assume it was big enough.
(binary_expression
  left: (call_expression function: (identifier) @lfn)
  operator: "+"
  right: (call_expression function: (identifier) @rfn)
  (#eq? @lfn "strlen")
  (#eq? @rfn "strlen")) @hit
