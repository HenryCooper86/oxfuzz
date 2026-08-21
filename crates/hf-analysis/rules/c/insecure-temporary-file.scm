; CWE-377: Insecure Temporary File
; SEI CERT C FIO21-C: mktemp, tmpnam, and tempnam return a name rather than an
; open descriptor, so the window between the name being chosen and the file
; being created is attacker-usable.
(call_expression
  function: (identifier) @fn
  ; mkstemp and mkstemps are the recommended replacements -- they return an open
; descriptor rather than a name -- so they must not be flagged.
  (#match? @fn "^(mktemp|tmpnam|tempnam)$")) @hit
