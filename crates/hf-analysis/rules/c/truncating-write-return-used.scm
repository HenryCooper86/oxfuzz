; CWE-131: Incorrect Calculation of Buffer Size
; SEI CERT C STR31-C: snprintf returns the length it *would* have written, not
; the length it wrote. Using that value as a count or an offset walks past the
; end of the buffer whenever the output was truncated, which an unbounded
; conversion makes reachable.
;
; A format with only width-bounded conversions cannot truncate, so the value is
; safe to use and the corpus marks those as acceptable.
;
; The two shapes are separate patterns rather than an alternation because a
; predicate applies to the pattern it sits inside; written after a top-level
; alternation it is silently not applied and the rule matches everything.
(assignment_expression
  right: (call_expression
    function: (identifier) @fn
    arguments: (argument_list (string_literal) @fmt))
  (#match? @fn "^(snprintf|vsnprintf)$")
  (#match? @fmt "%[^%diouxXeEfgGcp]*(s|\\[)")) @hit

(init_declarator
  value: (call_expression
    function: (identifier) @fn
    arguments: (argument_list (string_literal) @fmt))
  (#match? @fn "^(snprintf|vsnprintf)$")
  (#match? @fmt "%[^%diouxXeEfgGcp]*(s|\\[)")) @hit
