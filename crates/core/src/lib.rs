//! gone-core: the auditable engine behind the gone privacy auditor.
//!
//! Layers, bottom to top:
//! - [`io`]: evidence sources (raw images, E01, AFF4, sparsebundle, devices)
//! - [`volume`]: partition tables (GPT, MBR, APM)
//! - [`fs`]: uniform filesystem access over vetted parser crates
//! - [`scan`]: free-space mapping, entropy classification, signature scanning
//! - [`carve`]: deleted-file carving and validation
//! - [`sanitize`]: secure deletion and free-space sanitization
//! - [`scrub`]: metadata removal from live files
//! - [`verify`]: post-sanitize verification and signed certificates
//! - [`trimdetect`]: media, TRIM, and encryption introspection
//! - [`report`]: findings, scores, and certificate models
#![forbid(unsafe_code)]

pub mod carve;
pub mod fs;
pub mod io;
pub mod report;
pub mod sanitize;
pub mod scan;
pub mod scrub;
pub mod trimdetect;
pub mod verify;
pub mod volume;
