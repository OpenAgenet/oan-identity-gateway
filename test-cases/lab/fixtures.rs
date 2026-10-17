// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
use serde_json::Value;
use std::path::PathBuf;
pub fn lab_root() -> PathBuf {
    std::env::var_os("OAN_LAB_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../oan-agent-integration-lab")
        })
}
pub fn read(relative: &str) -> Value {
    let text = std::fs::read_to_string(lab_root().join(relative))
        .expect("lab fixture missing: clone oan-agent-integration-lab or set OAN_LAB_ROOT");
    serde_json::from_str(text.trim_start_matches('\u{feff}')).expect("invalid lab fixture JSON")
}
pub fn manifest() -> Value {
    read("config/oan-identities.json")
}
pub fn document(actor: &Value) -> Value {
    read(actor["materials"]["didDocument"].as_str().unwrap())
}
pub fn resource_names() -> [&'static str; 5] {
    ["a2a-a", "a2a-b", "mcp", "hermes-a", "hermes-b"]
}
