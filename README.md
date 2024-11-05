# Rust Binary Samples & Evaluation Scripts

## Dependencies
- [`uv`](https://docs.astral.sh/uv/)
- [`rustup`](https://rustup.rs/)
- [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) (for cross-compilation of Windows binaries)
- Working IDA Pro 9.0 (as `ida`) with Rust signature generation plugin

## Instructions
```bash
uv run build.py
uv run evaluate.py
uv run summary.py
```
