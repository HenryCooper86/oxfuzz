; CWE-252: Unchecked Return Value
; SEI CERT C ERR33-C: the scanf family returns the number of fields assigned;
; discarding it leaves every destination indeterminate on a short or failed
; read. The expression_statement parent is what "result discarded" means
; syntactically: a call in an if-condition or an initializer has a different
; parent and is therefore checked.
(expression_statement
  (call_expression
    function: (identifier) @fn
    (#match? @fn "^(scanf|fscanf|sscanf)$")) @hit)
