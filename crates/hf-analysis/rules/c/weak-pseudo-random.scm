; CWE-338: Use of Cryptographically Weak PRNG
; SEI CERT C MSC30-C: rand and srand produce a predictable sequence, so any
; value derived from them is guessable by anyone who can observe or infer the
; seed.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(rand|srand|random|srandom|drand48|lrand48)$")) @hit
