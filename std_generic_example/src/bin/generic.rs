fn main() {
    let mut vec = Vec::new();
    for i in (0..100usize).rev() {
        vec.push(i);
    }
    vec.sort();
    println!("{}", vec.iter().sum::<usize>());
}
