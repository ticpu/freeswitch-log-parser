use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub monitor: MonitorConfig,
    #[serde(default)]
    pub tools: Vec<Tool>,
}

#[derive(Deserialize)]
pub struct MonitorConfig {
    #[serde(default = "default_linger")]
    pub hangup_linger_seconds: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        MonitorConfig {
            hangup_linger_seconds: default_linger(),
        }
    }
}

fn default_linger() -> u64 {
    3600
}

#[derive(Deserialize, Clone)]
pub struct Tool {
    pub name: String,
    pub command: String,
}

impl Tool {
    pub fn expand_command(&self, uuid: &str) -> String {
        self.command.replace("{{uuid}}", uuid)
    }
}

/// A directory named by an environment variable. A value set but unreadable is
/// a misconfiguration, and reading it as unset is how it stays invisible.
fn env_dir(name: &str) -> anyhow::Result<Option<PathBuf>> {
    match std::env::var(name) {
        Ok(v) => Ok(Some(PathBuf::from(v))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(anyhow::Error::new(e).context(format!("{name} is set but unusable"))),
    }
}

pub fn find_config(explicit: Option<&Path>) -> anyhow::Result<Option<PathBuf>> {
    if let Some(p) = explicit {
        return Ok(Some(p.to_path_buf()));
    }
    if let Some(xdg) = env_dir("XDG_CONFIG_HOME")? {
        let p = xdg.join("fslog/config.yaml");
        if p.exists() {
            return Ok(Some(p));
        }
    }
    if let Some(home) = env_dir("HOME")? {
        let p = home.join(".config/fslog/config.yaml");
        if p.exists() {
            return Ok(Some(p));
        }
    }
    let p = PathBuf::from("/etc/fslog/config.yaml");
    if p.exists() {
        return Ok(Some(p));
    }
    Ok(None)
}

pub fn load_config(explicit: Option<&Path>) -> anyhow::Result<Config> {
    let Some(path) = find_config(explicit)? else {
        return Ok(Config::default());
    };
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_yml::from_str(&content).with_context(|| format!("parsing {}", path.display()))
}
