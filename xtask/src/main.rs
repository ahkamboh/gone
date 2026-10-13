//! xtask: build automation entry point (cargo xtask convention).

fn main() {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("package-rules") => println!("package-rules: not implemented yet"),
        Some(other) => eprintln!("unknown task: {other}"),
        None => eprintln!("usage: cargo xtask <task>  (tasks: package-rules)"),
    }
}
