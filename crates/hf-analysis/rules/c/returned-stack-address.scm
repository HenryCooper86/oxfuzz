; CWE-562: Return of Stack Variable Address
; SEI CERT C DCL30-C: the frame is gone when the caller reads through the
; returned pointer, so it names memory that has been reused.
(return_statement (pointer_expression "&" argument: (identifier))) @hit
