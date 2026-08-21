; CWE-683: Function Call With Incorrect Order of Arguments
; SEI CERT C EXP37-C: memset is (dest, value, length). Passing a literal zero
; as the third argument writes nothing, so a buffer the author believed was
; scrubbed still holds its previous contents.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    .
    (_)
    (_)
    (number_literal) @len
    .)
  (#eq? @fn "memset")
  (#eq? @len "0")) @hit
