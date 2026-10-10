//! Binary-level tests for config directory resolution: precedence across
//! `--config` / `HF_CONFIG_DIR` / the per-user config dir / the source-tree
//! walk-up, the walk-up stderr warning, and fail-loud validation of explicit
//! overrides. Uses the standard isolation pattern: private HOME, `HF_DB_PATH`,
//! `HF_WORKSPACE_DIR`, `HF_USE_DOCKER=0`.

use std::path::PathBuf;
use std::process::{Command, Output};

/// A throwaway oxfuzz environment: private HOME (so the real per-user config
/// never interferes), a database, a workspace, and a foreign source tree
/// (`Cargo.toml` + `config/`) to drive the walk-up fallback.
struct Fixture {
    directory: tempfile::TempDir,
    home: PathBuf,
    tree: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary fixture root");
        let home = directory.path().join("home");
        let tree = directory.path().join("foreign-tree");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(tree.join("config")).unwrap();
        std::fs::write(tree.join("Cargo.toml"), "[package]\nname = \"foreign\"\n").unwrap();
        Self {
            directory,
            home,
            tree,
        }
    }

    fn tree_config(&self) -> PathBuf {
        self.tree.join("config")
    }

    /// The child's `std::env::current_dir()` is canonicalized by the OS (on
    /// macOS `/var/...` resolves to `/private/var/...`), while `HOME` is used
    /// verbatim -- expectations must match each input's treatment.
    fn canonical_tree_config(&self) -> PathBuf {
        std::fs::canonicalize(self.tree_config()).unwrap()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// The per-user config dir the child process resolves for the private
    /// HOME, replicating `platform_user_app_dir` per platform.
    fn user_config_dir(&self) -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            self.home
                .join("Library")
                .join("Application Support")
                .join("oxfuzz")
                .join("config")
        }
        #[cfg(target_os = "windows")]
        {
            self.path("appdata").join("oxfuzz").join("config")
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            self.path("xdg").join("oxfuzz").join("config")
        }
    }

    /// Run the CLI with the isolated base environment; callers add or remove
    /// variables via the returned command.
    fn oxfuzz(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oxfuzz"));
        command
            .current_dir(&self.tree)
            .env("HF_DB_PATH", self.path("oxfuzz.db"))
            .env("HF_WORKSPACE_DIR", self.path("workspace"))
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", self.path("xdg"))
            .env("APPDATA", self.path("appdata"))
            .env("HF_USE_DOCKER", "0")
            .env_remove("HF_CONFIG_DIR")
            .env_remove("HF_PROVIDER_API_KEY");
        command
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn the_walk_up_fallback_binds_the_enclosing_tree_and_warns_on_stderr() {
    let fixture = Fixture::new();

    let output = fixture.oxfuzz().args(["runs", "list"]).output().unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    let stderr = stderr(&output);
    assert!(
        stderr.contains(&format!(
            "config directory '{}' comes from the source tree",
            fixture.canonical_tree_config().display()
        )),
        "the warning names the resolved dir: {stderr}"
    );
    assert!(
        stderr.contains("set HF_CONFIG_DIR to pin one explicitly"),
        "the warning names the override: {stderr}"
    );
    assert!(stdout(&output).contains("No runs recorded."));
}

#[test]
fn hf_config_dir_wins_over_the_walk_up_without_a_warning() {
    let fixture = Fixture::new();
    let explicit = fixture.path("explicit-config");

    let output = fixture
        .oxfuzz()
        .args(["runs", "list"])
        .env("HF_CONFIG_DIR", &explicit)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("config directory"),
        "an explicit env override is never warned about: {}",
        stderr(&output)
    );
    // The explicit dir is honored: bootstrap created it on demand.
    assert!(explicit.is_dir());
}

#[test]
fn a_live_per_user_config_shadows_a_source_checkout_and_says_so() {
    let fixture = Fixture::new();
    let user_config = fixture.user_config_dir();
    std::fs::create_dir_all(&user_config).unwrap();
    std::fs::write(user_config.join("providers.toml"), "providers = []\n").unwrap();

    let output = fixture.oxfuzz().args(["runs", "list"]).output().unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    let stderr = stderr(&output);
    assert!(
        stderr.contains(&format!(
            "config directory '{}' (per-user) shadows the source tree config at '{}'",
            user_config.display(),
            fixture.canonical_tree_config().display()
        )),
        "the shadowing is named both ways: {stderr}"
    );
    assert!(
        !stderr.contains("comes from the source tree"),
        "the walk-up did not win: {stderr}"
    );
}

#[test]
fn a_bare_per_user_config_dir_does_not_shadow_a_source_checkout() {
    let fixture = Fixture::new();
    // Created (e.g. by an earlier bootstrap) but holding no live config files.
    std::fs::create_dir_all(fixture.user_config_dir()).unwrap();

    let output = fixture.oxfuzz().args(["runs", "list"]).output().unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("comes from the source tree"),
        "the dev flow still binds the checkout: {}",
        stderr(&output)
    );
}

#[test]
fn the_config_flag_wins_and_init_materializes_into_it() {
    let fixture = Fixture::new();
    let flagged = fixture.path("flagged-config");
    let flagged_after = fixture.path("flagged-after-config");

    // Before the subcommand.
    let output = fixture
        .oxfuzz()
        .args(["--config"])
        .arg(&flagged)
        .arg("init")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains(&flagged.display().to_string()));
    assert!(flagged.join("oxfuzz.toml").is_file());
    assert!(flagged.join("providers.toml").is_file());

    // After the subcommand (global flag), and `init` itself never warns.
    let output = fixture
        .oxfuzz()
        .arg("init")
        .arg("--config")
        .arg(&flagged_after)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(flagged_after.join("oxfuzz.toml").is_file());
    assert!(
        !stderr(&output).contains("config directory"),
        "init prints no resolution warning: {}",
        stderr(&output)
    );
}

#[test]
fn init_inside_a_source_tree_warns_about_nothing() {
    let fixture = Fixture::new();

    let output = fixture.oxfuzz().arg("init").output().unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("warning: config directory"),
        "init never warns: {}",
        stderr(&output)
    );
    // The walk-up bound the enclosing tree, so init wrote there.
    assert!(fixture.tree_config().join("oxfuzz.toml").is_file());
}

#[test]
fn an_explicit_config_dir_that_is_a_file_fails_loud() {
    let fixture = Fixture::new();
    let file = fixture.path("not-a-dir");
    std::fs::write(&file, "occupied\n").unwrap();

    let env_output = fixture
        .oxfuzz()
        .args(["runs", "list"])
        .env("HF_CONFIG_DIR", &file)
        .output()
        .unwrap();
    assert!(!env_output.status.success());
    let env_stderr = stderr(&env_output);
    assert!(env_stderr.contains("HF_CONFIG_DIR"), "{env_stderr}");
    assert!(env_stderr.contains("not a directory"), "{env_stderr}");
    assert!(
        env_stderr.contains(&file.display().to_string()),
        "{env_stderr}"
    );

    let flag_output = fixture
        .oxfuzz()
        .arg("--config")
        .arg(&file)
        .args(["runs", "list"])
        .output()
        .unwrap();
    assert!(!flag_output.status.success());
    let flag_stderr = stderr(&flag_output);
    assert!(flag_stderr.contains("--config"), "{flag_stderr}");
    assert!(flag_stderr.contains("not a directory"), "{flag_stderr}");
}

#[test]
fn the_walk_up_binding_is_functional_for_provider_config() {
    let fixture = Fixture::new();
    // Plant a provider in the foreign tree's config: the listing proves the
    // resolved config dir is the one actually read, not merely named.
    std::fs::write(
        fixture.tree_config().join("providers.toml"),
        "[[providers]]\nid = \"tree-proof\"\nprovider_type = \"openai-compat\"\nmodel = \"gpt-4o\"\napi_key = \"sk-test\"\n",
    )
    .unwrap();

    let output = fixture.oxfuzz().args(["providers"]).output().unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("tree-proof"),
        "the tree's provider config is what the CLI reads: {}",
        stdout(&output)
    );
}

#[test]
fn hf_config_dir_points_provider_reads_at_the_explicit_dir() {
    let fixture = Fixture::new();
    let explicit = fixture.path("explicit-config");
    std::fs::create_dir_all(&explicit).unwrap();
    std::fs::write(
        explicit.join("providers.toml"),
        "[[providers]]\nid = \"explicit-proof\"\nprovider_type = \"openai-compat\"\nmodel = \"gpt-4o\"\napi_key = \"sk-test\"\n",
    )
    .unwrap();
    // A provider in the walked-up tree must NOT be read.
    std::fs::write(
        fixture.tree_config().join("providers.toml"),
        "[[providers]]\nid = \"tree-proof\"\nprovider_type = \"openai-compat\"\nmodel = \"gpt-4o\"\napi_key = \"sk-test\"\n",
    )
    .unwrap();

    let output = fixture
        .oxfuzz()
        .args(["providers"])
        .env("HF_CONFIG_DIR", &explicit)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("explicit-proof"), "{stdout}");
    assert!(!stdout.contains("tree-proof"), "{stdout}");
}
