# Rust Binary Samples & Evaluation Scripts

## Dependencies
- [`uv`](https://docs.astral.sh/uv/)
- [`rustup`](https://rustup.rs/)
- [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) (for cross-compilation of Windows binaries)
- [`signature_generator`](TODO) (CLI version; `cargo install --path .` in signature_generator repository)
- IDA Pro 9.0 (as `ida`) with Rust signature generation plugin

## Instructions
```bash
# python /path/to/ida-pro-9.0/idalib/python/py-activate-idalib.py
ln -s /path/to/ida-pro-9.0/idalib/python idalib
```

```bash
uv run build.py
uv run evaluate.py
uv run summary.py
```

```bash
uv run evaluate_uniqueness.py
```
