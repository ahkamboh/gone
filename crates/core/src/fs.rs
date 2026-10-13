//! Uniform filesystem access.
//!
//! Thin wrappers over vetted parser crates (`ntfs`, `ext4-view`, `apfs-core`,
//! `fat-core`) exposing one API: list allocated tree, read file, fs metadata.
