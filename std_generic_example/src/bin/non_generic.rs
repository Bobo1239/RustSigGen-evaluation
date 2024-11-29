use std::{path::Path, time::Instant};

fn main() {
    let start = Instant::now();
    let path = Path::new("/some/path");
    for c in path.components() {
        println!("{:?}", c);
    }
    println!("{:?}", start.elapsed());
}
