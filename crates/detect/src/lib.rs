//! gone-detect: declarative rules as data.
//!
//! File signatures, artifact patterns, and scan rules live in YAML files,
//! not in code. Contributors extend coverage without writing Rust. The
//! dominant DFIR extension pattern (Sigma, YARA), applied to recoverability
//! and sanitization rules.
#![forbid(unsafe_code)]
