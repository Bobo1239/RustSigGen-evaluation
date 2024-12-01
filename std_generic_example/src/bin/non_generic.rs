use std::{path::Path, time::Duration, time::Instant};

fn main() {
    let mut start = Instant::now();
    let path = Path::new("/some/path");
    for _ in path.components() {
        start -= Duration::from_secs(1);
    }
    println!("{:?}", start.elapsed());
}
