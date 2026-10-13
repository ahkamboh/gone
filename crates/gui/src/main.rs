//! gone desktop app entry point. The app itself lives in the library
//! crate so integration tests and mobile entry points can reuse it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    gone_gui::run();
}
