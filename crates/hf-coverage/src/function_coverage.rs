//! Function counters from an LLVM export, without inferring missing measurements.

use serde::{Deserialize, Serialize};

/// One function's counters and associated source files in a measured binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCoverage {
    pub name: String,
    pub count: u64,
    pub files: Vec<String>,
}

#[derive(Deserialize)]
struct Export {
    data: Vec<Data>,
}

#[derive(Deserialize)]
struct Data {
    functions: Vec<Function>,
}

#[derive(Deserialize)]
struct Function {
    name: String,
    count: u64,
    filenames: Vec<String>,
}

/// Parse each measured function, preserving separate same-named definitions.
///
/// # Errors
/// Rejects absent/malformed counters, source names, empty exports, or oversized input.
pub fn parse_llvm_function_coverage(json: &str) -> Result<Vec<FunctionCoverage>, String> {
    if json.len() > 8 * 1024 * 1024 {
        return Err("function coverage export exceeds 8 MiB".to_owned());
    }
    let export: Export = serde_json::from_str(json).map_err(|error| error.to_string())?;
    if export.data.is_empty() {
        return Err("function coverage export contains no data".to_owned());
    }
    let mut functions = Vec::new();
    for data in export.data {
        for function in data.functions {
            if functions.len() >= 100_000
                || function.name.is_empty()
                || function.filenames.is_empty()
                || function.filenames.iter().any(String::is_empty)
            {
                return Err(
                    "function coverage export has missing identity or excessive functions"
                        .to_owned(),
                );
            }
            functions.push(FunctionCoverage {
                name: function.name,
                count: function.count,
                files: function.filenames,
            });
        }
    }
    Ok(functions)
}
