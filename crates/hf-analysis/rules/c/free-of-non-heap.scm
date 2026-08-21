; CWE-590: Free of Memory not on the Heap
; SEI CERT C MEM34-C: free may only be called on a pointer the allocator
; returned. Passing the address of a local corrupts the allocator's bookkeeping
; immediately.
;
; The operator is matched explicitly because tree-sitter uses pointer_expression
; for both `&x` and `*x`, and `free(*pp)` is ordinary code.
(call_expression
  function: (identifier) @fn
  arguments: (argument_list (pointer_expression "&"))
  (#eq? @fn "free")) @hit
