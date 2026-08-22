; CWE-1260: Improper Handling of Overlap Between Memory Ranges
; SEI CERT C EXP43-C and STR38-C: copying a buffer onto itself is undefined.
; The printf family is worse than memcpy here, because it reads the source
; while writing the destination and mangles the result on most targets.
;
; The destination is the first argument; a defect is that same name appearing
; again as a source. Writing through a separate temporary, which is the fix, is
; not matched.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list
    .
    (identifier) @dst
    (identifier) @src)
  (#match? @fn "^(memcpy|wmemcpy|memmove|strcpy|strcat|sprintf|snprintf|vsprintf|vsnprintf)$")
  (#eq? @dst @src)) @hit
