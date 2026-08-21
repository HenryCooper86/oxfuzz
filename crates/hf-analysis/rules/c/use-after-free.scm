; CWE-416: Use After Free
; SEI CERT C MEM30-C: after free the pointer's target may be reallocated, so a
; later read returns another object's bytes and a later write corrupts it.
;
; The free is the @origin and every later mention of the same name is a @site.
; The driver reports the first site that follows an origin with nothing between
; them that could have changed what the name refers to.
[
  (call_expression
    function: (identifier) @fn
    arguments: (argument_list (identifier) @var)
    (#eq? @fn "free")) @origin
  ((identifier) @site @var)
]
