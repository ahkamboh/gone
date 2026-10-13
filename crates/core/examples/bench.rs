//! Microbenchmark: separate cipher throughput from disk throughput so we
//! know which half of the sanitize loop is slow.
//!
//! Run with: cargo run --release -p gone-core --example bench

use std::io::Write;
use std::time::Instant;

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

const CHUNK: usize = 4 * 1024 * 1024;
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

fn main() {
    println!(
        "cfg features: aes={} neon={} sha2={}",
        cfg!(target_feature = "aes"),
        cfg!(target_feature = "neon"),
        cfg!(target_feature = "sha2")
    );
    let total_chunks = 512; // 2 GiB worth
    let mut buf = vec![0u8; CHUNK];

    // 1. Cipher only: keystream over a zeroed buffer, no I/O.
    let key = [7u8; 32];
    let iv = [3u8; 16];
    let mut cipher = Aes256Ctr::new_from_slices(&key, &iv).unwrap();
    let t = Instant::now();
    for _ in 0..total_chunks {
        buf.fill(0);
        cipher.apply_keystream(&mut buf);
    }
    let el = t.elapsed().as_secs_f64();
    let gib = total_chunks as f64 * CHUNK as f64 / GIB;
    println!(
        "cipher only : {gib:.1} GiB in {el:.2}s = {:.2} GiB/s",
        gib / el
    );

    // 2. Disk only: write an already-random buffer, no cipher.
    let path = std::env::temp_dir().join(format!("gone-bench-{}", std::process::id()));
    let mut file = std::fs::File::create(&path).unwrap();
    let t = Instant::now();
    for _ in 0..total_chunks {
        file.write_all(&buf).unwrap();
    }
    file.sync_data().unwrap();
    let el = t.elapsed().as_secs_f64();
    println!(
        "disk only   : {gib:.1} GiB in {el:.2}s = {:.2} GiB/s",
        gib / el
    );
    drop(file);
    std::fs::remove_file(&path).unwrap();

    // 3. Combined, same shape as sanitize::run.
    let mut cipher = Aes256Ctr::new_from_slices(&key, &iv).unwrap();
    let mut file = std::fs::File::create(&path).unwrap();
    let t = Instant::now();
    for _ in 0..total_chunks {
        buf.fill(0);
        cipher.apply_keystream(&mut buf);
        file.write_all(&buf).unwrap();
    }
    file.sync_data().unwrap();
    let el = t.elapsed().as_secs_f64();
    println!(
        "combined    : {gib:.1} GiB in {el:.2}s = {:.2} GiB/s",
        gib / el
    );
    drop(file);
    std::fs::remove_file(&path).unwrap();
}
