; CWE-686: Function Call With Incorrect Argument Type
; SEI CERT C POS34-C: putenv keeps the pointer it is given rather than copying,
; so passing anything with a shorter lifetime than the environment leaves a
; dangling entry the next getenv returns.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list . (identifier) .)
  (#eq? @fn "putenv")) @hit
