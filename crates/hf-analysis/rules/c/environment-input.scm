; CWE-15: External Control of System or Configuration Setting
; SEI CERT C ENV33-C and STR31-C: getenv returns attacker-influenced bytes of
; unbounded length under a name the process does not control, so every use is
; an untrusted input source worth fuzzing.
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(getenv|secure_getenv)$")) @hit
