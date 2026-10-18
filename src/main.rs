// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use oan_identity_gateway::{capabilities, config::Config};
fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("capabilities") => {
            println!("{}", serde_json::to_string_pretty(&capabilities()).unwrap())
        }
        Some("check-config") => {
            let result = args
                .next()
                .ok_or_else(|| "missing_config_path".to_string())
                .and_then(|path| {
                    std::fs::read_to_string(path).map_err(|_| "config_read_failed".to_string())
                })
                .and_then(|text| {
                    serde_json::from_str::<Config>(&text)
                        .map_err(|_| "invalid_config_json".to_string())
                })
                .and_then(|config| config.validate().map_err(|e| e.to_string()));
            match result {
                Ok(()) => println!("config_valid"),
                Err(code) => {
                    eprintln!("{code}");
                    std::process::exit(2);
                }
            }
        }
        Some("serve") => {
            let path = args.next().ok_or_else(|| "missing_config_path".to_string());
            let result = path
                .and_then(|path| {
                    std::fs::read_to_string(path).map_err(|_| "config_read_failed".to_string())
                })
                .and_then(|text| {
                    serde_json::from_str::<Config>(&text)
                        .map_err(|_| "invalid_config_json".to_string())
                })
                .and_then(|config| {
                    tokio::runtime::Runtime::new()
                        .map_err(|_| "runtime_init_failed".to_string())
                        .and_then(|rt| {
                            rt.block_on(oan_identity_gateway::server::serve(config))
                                .map_err(|e| e.to_string())
                        })
                });
            if let Err(code) = result {
                eprintln!("{code}");
                std::process::exit(2);
            }
        }
        _ => println!("Usage: oan-identity-gateway capabilities | check-config <path>"),
    }
}
