//! Per-translation-unit compiler inputs; raw project commands are never executed.
use super::snapshot::{digest, invalid};
use hf_core::{build::CompileEntry, error::ClassifiedError};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnitRequest {
    pub id: String,
    pub file: String,
    pub scope: String,
    pub directory: String,
    pub arguments: Vec<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeUnit {
    file: String,
    invocation_sha256: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeManifest {
    schema_version: u32,
    name: String,
    compile_database_sha256: String,
    units: Vec<ScopeUnit>,
}

fn mapped(
    project: &Path,
    directory: &Path,
    raw: &str,
    file: bool,
) -> Result<String, ClassifiedError> {
    let path = std::fs::canonicalize(directory.join(raw))
        .map_err(|_| invalid("compiler path is missing"))?;
    if !path.starts_with(project) || (file && !path.is_file()) {
        return Err(invalid("compiler input outside project"));
    }
    let relative_path = path
        .strip_prefix(project)
        .map_err(|e| invalid(e.to_string()))?;
    relative_path
        .to_str()
        .ok_or_else(|| invalid("non-UTF8 compiler path"))?;
    let relative = hf_core::runtime::posix_relative(relative_path);
    if relative.contains(['\\', ':']) {
        return Err(invalid("nonportable compiler path"));
    }
    Ok(if relative.is_empty() {
        "/work/source".into()
    } else {
        format!("/work/source/{relative}")
    })
}

fn cpp_driver(arguments: &[String]) -> Result<bool, ClassifiedError> {
    let name = arguments
        .first()
        .and_then(|driver| Path::new(driver).file_name())
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("missing compiler driver"))?;
    let name = name.strip_suffix(".exe").unwrap_or(name);
    let base = name
        .rsplit_once('-')
        .filter(|(_, version)| {
            !version.is_empty()
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
        })
        .map_or(name, |(base, _)| base);
    match base {
        "clang++" | "g++" | "c++" => Ok(true),
        "clang" | "gcc" | "cc" => Ok(false),
        _ => Err(invalid(
            "unsupported compiler driver; use a direct C/C++ invocation",
        )),
    }
}

pub(crate) fn resolve_units(
    entries: &[CompileEntry],
    project: &Path,
    database_sha: &str,
    scope: Option<&[u8]>,
    max_units: usize,
) -> Result<Vec<UnitRequest>, ClassifiedError> {
    if entries.is_empty() || entries.len() > max_units {
        return Err(invalid("compiler unit count limit or empty database"));
    }
    let mut units = Vec::new();
    for entry in entries {
        let directory = std::fs::canonicalize(project.join(&entry.directory))
            .map_err(|_| invalid("compiler directory missing"))?;
        let workdir = mapped(project, &directory, ".", false)?;
        let source = mapped(
            project,
            &directory,
            entry
                .file
                .to_str()
                .ok_or_else(|| invalid("non-UTF8 source"))?,
            true,
        )?;
        let file = source
            .strip_prefix("/work/source/")
            .ok_or_else(|| invalid("invalid source file"))?
            .to_owned();
        let mut args = if cpp_driver(&entry.arguments)? {
            vec!["-x".into(), "c++".into()]
        } else {
            Vec::new()
        };
        let mut input_seen = false;
        let mut iter = entry.arguments.iter().skip(1);
        while let Some(arg) = iter.next() {
            if arg.len() > 4096 || arg.contains(['\0', '\n', '\r']) {
                return Err(invalid("invalid compiler argument"));
            }
            if arg.starts_with("-Wp,") || arg.starts_with("-Wl,") || arg.starts_with("-Wa,") {
                return Err(invalid("unsupported compiler passthrough argument"));
            }
            if ["-c", "-S", "-g", "-pipe", "-fno-omit-frame-pointer"].contains(&arg.as_str())
                || arg.starts_with("-W")
            {
                continue;
            }
            if [
                "-O0", "-O1", "-O2", "-O3", "-Os", "-Oz", "-Og", "-Ofast", "-fPIC", "-fPIE",
            ]
            .contains(&arg.as_str())
            {
                args.push(arg.clone());
                continue;
            }
            if ["-o", "-MF", "-MT", "-MQ"].contains(&arg.as_str()) {
                iter.next()
                    .ok_or_else(|| invalid("missing compiler output argument"))?;
                continue;
            }
            if ["-MD", "-MMD", "-MP"].contains(&arg.as_str()) {
                continue;
            }
            if ["-I", "-isystem", "-iquote", "-include", "-imacros"].contains(&arg.as_str()) {
                let raw = iter
                    .next()
                    .ok_or_else(|| invalid("missing include argument"))?;
                args.push(arg.clone());
                args.push(mapped(
                    project,
                    &directory,
                    raw,
                    ["-include", "-imacros"].contains(&arg.as_str()),
                )?);
                continue;
            }
            if let Some(raw) = arg.strip_prefix("-I").filter(|v| !v.is_empty()) {
                args.push(format!("-I{}", mapped(project, &directory, raw, false)?));
                continue;
            }
            if ["-D", "-U"].contains(&arg.as_str()) {
                let value = iter
                    .next()
                    .ok_or_else(|| invalid("missing macro argument"))?;
                if value.contains(['\0', '\n', '\r']) {
                    return Err(invalid("invalid macro"));
                }
                args.push(format!("{arg}{value}"));
                continue;
            }
            if arg.starts_with("-D")
                || arg.starts_with("-U")
                || arg.starts_with("-std=")
                || [
                    "-pthread",
                    "-fno-strict-aliasing",
                    "-fwrapv",
                    "-funsigned-char",
                    "-fno-common",
                ]
                .contains(&arg.as_str())
            {
                args.push(arg.clone());
                continue;
            }
            if arg == "-x" {
                let lang = iter.next().ok_or_else(|| invalid("missing language"))?;
                if !["c", "c++"].contains(&lang.as_str()) {
                    return Err(invalid("unsupported compiler language"));
                }
                args.extend([arg.clone(), lang.clone()]);
                continue;
            }
            if !arg.starts_with('-')
                && !arg.starts_with('@')
                && mapped(project, &directory, arg, true)? == source
                && !input_seen
            {
                input_seen = true;
                continue;
            }
            return Err(invalid("unsupported semantic compiler argument"));
        }
        if !input_seen {
            return Err(invalid("compiler invocation has no matching source"));
        }
        let id = digest(
            &serde_json::to_vec(&(&file, &workdir, &args)).map_err(|e| invalid(e.to_string()))?,
        );
        units.push(UnitRequest {
            id: id.clone(),
            file,
            scope: id,
            directory: workdir,
            arguments: args,
        });
    }
    units.sort_by(|a, b| a.id.cmp(&b.id));
    units.dedup_by(|a, b| a.id == b.id);
    if let Some(bytes) = scope {
        let manifest: ScopeManifest =
            serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
        if manifest.schema_version != 1
            || manifest.name.trim().is_empty()
            || manifest.name.len() > 1024
            || manifest.compile_database_sha256 != database_sha
            || manifest.units.is_empty()
        {
            return Err(invalid("invalid or stale scope manifest"));
        }
        let mut selected = Vec::new();
        let mut files = BTreeSet::new();
        for selection in manifest.units {
            if !files.insert(selection.file.clone()) {
                return Err(invalid("scope selects multiple variants of one file"));
            }
            let matched = units
                .iter()
                .find(|u| u.file == selection.file && u.id == selection.invocation_sha256)
                .ok_or_else(|| invalid("scope invocation does not resolve"))?;
            let mut unit = matched.clone();
            unit.scope = digest(bytes);
            selected.push(unit);
        }
        units = selected;
    }
    Ok(units)
}

/// Check main-source target membership before dispatching an explicitly scoped build.
pub(crate) fn validate_scope_selection(
    units: &[UnitRequest],
    target_files: &[String],
) -> Result<(), ClassifiedError> {
    for file in target_files {
        let header = Path::new(file).extension().is_some_and(|extension| {
            ["h", "hpp", "hxx", "hh", "inc"]
                .iter()
                .any(|allowed| extension == *allowed)
        });
        if !header && !units.iter().any(|unit| &unit.file == file) {
            return Err(invalid(
                "selected target is outside the declared linked scope",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(arguments: &[&str]) -> (tempfile::TempDir, Vec<CompileEntry>) {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("unit.c"), "int parse(int x){return x;}").unwrap();
        let entries = vec![CompileEntry {
            file: "unit.c".into(),
            directory: project.path().to_owned(),
            arguments: arguments.iter().map(|v| (*v).into()).collect(),
        }];
        (project, entries)
    }
    #[test]
    fn cpp_driver_language_is_explicit_and_unknown_drivers_are_rejected() {
        for driver in ["clang++", "/usr/bin/g++-12", "c++"] {
            let (root, entries) = fixture(&[driver, "-c", "unit.c"]);
            let units = resolve_units(
                &entries,
                &std::fs::canonicalize(root.path()).unwrap(),
                "digest",
                None,
                2,
            )
            .unwrap();
            assert_eq!(units[0].arguments, ["-x", "c++"]);
        }
        let (root, entries) = fixture(&["ccache", "-c", "unit.c"]);
        assert!(resolve_units(
            &entries,
            &std::fs::canonicalize(root.path()).unwrap(),
            "digest",
            None,
            2
        )
        .is_err());
        let (root, entries) = fixture(&["clang++", "-x", "c", "-c", "unit.c"]);
        let units = resolve_units(
            &entries,
            &std::fs::canonicalize(root.path()).unwrap(),
            "digest",
            None,
            2,
        )
        .unwrap();
        assert_eq!(units[0].arguments, ["-x", "c++", "-x", "c"]);
    }
    #[test]
    fn preprocessor_passthrough_is_rejected_rather_than_silently_dropped() {
        let (root, entries) = fixture(&["clang", "-Wp,-DFEATURE=1", "-c", "unit.c"]);
        assert!(resolve_units(
            &entries,
            &std::fs::canonicalize(root.path()).unwrap(),
            "digest",
            None,
            2
        )
        .is_err());
    }
    #[test]
    fn opposite_per_unit_macros_and_zero_flag_databases_remain_distinct() {
        let (root, mut entries) = fixture(&["clang", "-DFEATURE=1", "-UOLD", "-c", "unit.c"]);
        entries.push(CompileEntry {
            arguments: vec![
                "clang".into(),
                "-DFEATURE=0".into(),
                "-c".into(),
                "unit.c".into(),
            ],
            ..entries[0].clone()
        });
        let units = resolve_units(
            &entries,
            &std::fs::canonicalize(root.path()).unwrap(),
            "digest",
            None,
            2,
        )
        .unwrap();
        assert_ne!(units[0].id, units[1].id);
        assert!(units
            .iter()
            .any(|u| u.arguments == ["-DFEATURE=1", "-UOLD"]));
        assert!(units.iter().any(|u| u.arguments == ["-DFEATURE=0"]));
    }
}
