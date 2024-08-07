# Rust Binary Samples & Evaluation Scripts

## Dependencies
- [https://rye.astral.sh/](`rye`)
- [https://rustup.rs/](`rustup`)
- [https://www.maturin.rs/](`maturin`) (for building `rustc_demangle_py`)
- [https://github.com/rust-cross/cargo-xwin](`cargo-xwin`) (for cross-compilation of Windows binaries)
- Working IDA Pro (as `ida64`) with Rust signature generation plugin

## Instructions
```bash
rye sync
./build.py
./evaluate.py
./summary.py
```
