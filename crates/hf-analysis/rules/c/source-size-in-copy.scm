; CWE-806: Buffer Access Using Size of Source Buffer
; SEI CERT C ARR38-C: the bound must describe the destination. Deriving it from
; the source means the copy is bounded by what the attacker supplies rather
; than by the space available.
[
  (call_expression
    function: (identifier) @fn
    arguments: (argument_list
      .
      (identifier)
      (identifier) @src
      (sizeof_expression value: (parenthesized_expression (identifier) @size))
      .)
    (#match? @fn "^(memcpy|memmove|strncpy|strncat)$")
    (#eq? @src @size))
  (call_expression
    function: (identifier) @fn
    arguments: (argument_list
      .
      (identifier)
      (identifier) @src
      (call_expression
        function: (identifier) @len
        arguments: (argument_list (identifier) @size))
      .)
    (#match? @fn "^(memcpy|memmove|strncpy|strncat)$")
    (#eq? @len "strlen")
    (#eq? @src @size))
] @hit
