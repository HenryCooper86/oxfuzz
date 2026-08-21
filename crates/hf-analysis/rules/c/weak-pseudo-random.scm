; CWE-338: Use of Cryptographically Weak PRNG
; SEI CERT C MSC30-C: rand and srand produce a predictable sequence from a
; small state, so any value derived from them is guessable.
;
; random and srandom are excluded: they carry enough state that the corpus
; treats a properly seeded use as acceptable, and flagging them fired on
; correct code.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(rand|srand)$")) @hit
