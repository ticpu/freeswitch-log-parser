use std::path::{Path, PathBuf};

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

pub fn find_config(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    if let Ok(p) = std::env::var("FSLOG_CONFIG") {
        return Some(PathBuf::from(p));
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg).join("fslog/config.yaml");
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".config/fslog/config.yaml");
        if p.exists() {
            return Some(p);
        }
    }
    let p = PathBuf::from("/etc/fslog/config.yaml");
    if p.exists() {
        return Some(p);
    }
    None
}

pub fn load_config(explicit: Option<&Path>) -> Result<Config, String> {
    let path = match find_config(explicit) {
        Some(p) => p,
        None => return Ok(Config::default()),
    };
    let content = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_yml::from_str(&content).map_err(|e| format!("{}: {e}", path.display()))
}
