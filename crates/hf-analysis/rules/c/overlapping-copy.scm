; CWE-1260: Improper Handling of Overlap Between Memory Ranges
; SEI CERT C EXP43-C: memcpy is undefined when source and destination overlap.
; Passing the same identifier as both is the case a compiler will not warn
; about and that only misbehaves on some targets.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    .
    (identifier) @dst
    (identifier) @src
    (_)
    .)
  (#match? @fn "^(memcpy|wmemcpy)$")
  (#eq? @dst @src)) @hit
