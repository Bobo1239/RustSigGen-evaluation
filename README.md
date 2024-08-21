# Rust Binary Samples & Evaluation Scripts

## Dependencies
- [`uv`](https://docs.astral.sh/uv/)
- [`rustup`](https://rustup.rs/)
- [`maturin`](https://www.maturin.rs/) (for building `rustc_demangle_py`)
- [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) (for cross-compilation of Windows binaries)
- Working IDA Pro (as `ida64`) with Rust signature generation plugin

## Instructions
```bash
uv run build.py
uv run evaluate.py
uv run summary.py
```
