// Rust port of dastlite (PASSIVE core) — CLI entrypoint.
use serde_json::Value;
use std::{env, fs, process};

fn main() {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: dastlite <capture.json>");
            process::exit(2);
        }
    };
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(2);
        }
    };
    let data: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid JSON: {}", e);
            process::exit(2);
        }
    };
    let out = dastlite::scan_input(&data);
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
