//! Reading C parameters for the model-free harness template: which input is a
//! string, and stubs for callback typedefs.

use std::path::Path;

/// Headers scanned for a callback typedef, at most, and bytes per header.
const MAX_SCANNED_HEADERS: usize = 2_000;
const MAX_HEADER_BYTES: u64 = 1_024 * 1_024;

/// Words a parameter's type is made of when it is a plain integer.
const INTEGER_WORDS: [&str; 8] = [
    "unsigned", "signed", "short", "long", "int", "char", "const", "volatile",
];

/// A stub for a callback parameter: its name and its definition.
pub(super) struct CallbackStub {
    /// The stub's name, cast to the callback typedef for the call.
    pub name: String,
    pub definition: String,
}

/// The type part of one parameter declaration (`ini_handler handler` ->
/// `ini_handler`, `unsigned int n` -> `unsigned int`).
pub(super) fn param_type(param: &str) -> String {
    let param = param.trim();
    if let Some(star) = param.rfind('*') {
        return param[..=star].trim().to_owned();
    }
    let words: Vec<&str> = param.split_whitespace().collect();
    match words.split_last() {
        Some((last, rest))
            if !rest.is_empty()
                && !INTEGER_WORDS.contains(last)
                && last.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') =>
        {
            rest.join(" ")
        }
        _ => param.to_owned(),
    }
}

/// Whether `param` is a pointer to plain `char`, the C string type (an
/// `unsigned char` or `uint8_t` buffer is bytes, not text).
pub(super) fn is_c_string(param: &str) -> bool {
    if param.matches('*').count() != 1 {
        return false;
    }
    let ty = param_type(param);
    let words: Vec<&str> = ty
        .trim_end_matches('*')
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile"))
        .collect();
    words == ["char"]
}

/// A stub for the callback typedef `name`, when a header under `root`
/// declares it as `typedef RET (*name)(PARAMS);`. The stub takes the same
/// parameters and returns "continue": nothing for `void`, `NULL` for a
/// pointer, 1 otherwise (the convention of parser callbacks such as inih's
/// `ini_handler`, where 0 stops the parse with an error).
pub(super) fn callback_stub(root: &Path, name: &str) -> Option<CallbackStub> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let (ret, params) = find_typedef(root, name)?;
    let mut declared = Vec::new();
    let mut unused = Vec::new();
    for (index, param) in params
        .split(',')
        .map(str::trim)
        .filter(|param| !param.is_empty() && *param != "void")
        .enumerate()
    {
        // A nested function pointer or array parameter is beyond a stub.
        if param.contains('(') || param.contains('[') {
            return None;
        }
        declared.push(format!("{} p{index}", param_type(param)));
        unused.push(format!("    (void)p{index};"));
    }
    let stub = format!("oxfuzz_{name}_stub");
    let parameters = if declared.is_empty() {
        "void".to_owned()
    } else {
        declared.join(", ")
    };
    let ret = ret.trim();
    let returned = if ret == "void" {
        String::new()
    } else if ret.contains('*') {
        "    return NULL;\n".to_owned()
    } else {
        "    return 1;\n".to_owned()
    };
    let unused = if unused.is_empty() {
        String::new()
    } else {
        format!("{}\n", unused.join("\n"))
    };
    Some(CallbackStub {
        definition: format!("static {ret} {stub}({parameters}) {{\n{unused}{returned}}}"),
        name: format!("({name}){stub}"),
    })
}

/// `(return type, parameter list)` of `typedef RET (*name)(PARAMS);` in the
/// first header under `root` that declares it.
fn find_typedef(root: &Path, name: &str) -> Option<(String, String)> {
    let mut scanned = 0usize;
    find_typedef_in(root, name, &mut scanned)
}

fn find_typedef_in(directory: &Path, name: &str, scanned: &mut usize) -> Option<(String, String)> {
    let entries = std::fs::read_dir(directory).ok()?;
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        if *scanned >= MAX_SCANNED_HEADERS {
            return None;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if kind.is_dir() {
            if !entry.file_name().to_string_lossy().starts_with('.') {
                if let Some(found) = find_typedef_in(&path, name, scanned) {
                    return Some(found);
                }
            }
            continue;
        }
        let header = kind.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| matches!(extension, "h" | "hh" | "hpp" | "hxx"));
        if !header
            || entry
                .metadata()
                .map_or(true, |m| m.len() > MAX_HEADER_BYTES)
        {
            continue;
        }
        *scanned += 1;
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(found) = parse_typedef(&text, name) {
            return Some(found);
        }
    }
    None
}

/// Parse `typedef RET (*name)(PARAMS);` out of `text`, across line breaks.
///
/// When the header declares the typedef more than once under preprocessor
/// conditions, the last declaration is taken: in the common
/// `#if FEATURE ... #else default #endif` shape that is the default (inih
/// declares a five-parameter `ini_handler` only with `INI_HANDLER_LINENO`).
/// The call site casts the stub to the typedef, so another active variant
/// still compiles.
fn parse_typedef(text: &str, name: &str) -> Option<(String, String)> {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let marker = format!("(*{name})");
    let at = flat.rfind(&marker)?;
    let typedef_at = flat[..at].rfind("typedef ")?;
    // The typedef must end before the marker: no `;` between them.
    let ret = &flat[typedef_at + "typedef ".len()..at];
    if ret.contains(';') {
        return None;
    }
    let params = flat[at + marker.len()..]
        .trim_start()
        .strip_prefix('(')?;
    let close = params.find(')')?;
    Some((ret.trim().to_owned(), params[..close].trim().to_owned()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn parameters_are_read_by_type() {
        assert_eq!(super::param_type("ini_handler handler"), "ini_handler");
        assert_eq!(super::param_type("unsigned int n"), "unsigned int");
        assert_eq!(super::param_type("const char* s"), "const char*");
        assert!(super::is_c_string("const char* string"));
        assert!(!super::is_c_string("const unsigned char *data"));
        assert!(!super::is_c_string("const uint8_t *data"));
    }

    #[test]
    fn the_default_variant_of_a_conditional_typedef_is_taken() {
        let text = "#if INI_HANDLER_LINENO\ntypedef int (*ini_handler)(void* user, const char* section,\n    const char* name, const char* value, int lineno);\n#else\ntypedef int (*ini_handler)(void* user, const char* section,\n    const char* name, const char* value);\n#endif\n";
        assert_eq!(
            super::parse_typedef(text, "ini_handler").map(|(_, params)| params),
            Some("void* user, const char* section, const char* name, const char* value".to_owned())
        );
    }

    #[test]
    fn a_multiline_typedef_is_parsed() {
        let text = "typedef int (*ini_handler)(void* user, const char* section,\n    const char* name, const char* value);\n";
        assert_eq!(
            super::parse_typedef(text, "ini_handler"),
            Some((
                "int".to_owned(),
                "void* user, const char* section, const char* name, const char* value".to_owned()
            ))
        );
        assert_eq!(super::parse_typedef(text, "other"), None);
    }
}
