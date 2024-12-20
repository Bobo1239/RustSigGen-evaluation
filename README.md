# Rust Binary Samples & Evaluation Scripts

## Dependencies
- [`uv`](https://docs.astral.sh/uv/)
- [`rustup`](https://rustup.rs/)
- [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) (for cross-compilation of Windows binaries)
- [`rust-sig-gen`] (CLI version)
- IDA Pro 9.0 (as `ida`) with the RustSigGen plugin installed

## Instructions
Setup `rust-sig-gen` and IDA plugin:
```bash
cd /path/to/RustSigGen
cargo install --path .
just install-ida-plugin
```

Setup idalib and FLAIR for evaluation scripts:
```bash
# python /path/to/ida-pro-9.0/idalib/python/py-activate-idalib.py
ln -s /path/to/ida-pro-9.0/idalib/python idalib
# Adjust `FLAIR_PATH` in shared.py
```

Run evaluation scripts:
```bash
uv run build.py

uv run evaluate_std.py
uv run summary.py std

uv run evaluate_crates.py
uv run summary.py crates

uv run evaluate_uniqueness.py
```
