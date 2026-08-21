; CWE-415: Double Free
; SEI CERT C MEM30-C: freeing the same pointer twice corrupts the allocator's
; bookkeeping, and two later allocations can then return the same block.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list (identifier) @var)
  (#eq? @fn "free")) @site
