#!/usr/bin/env python3

from collections import ChainMap
from pathlib import Path
import subprocess
import json

from shared import TARGET_PATH, FLAIR_PATH

# NOTE: This assumes IDA Pro 9.0 (so the binary is just called `ida`)

# TODO: Would be cool to leverage the new idalib for this. But need to make plugin work optionally
#       without QT event loop.

EVALUATION_PATH = TARGET_PATH / "evaluation"
SIGNATURES_PATH = TARGET_PATH / "crate_sigs"

IDA_SCRIPT_PATH = Path(__file__).parent / "ida_scripts" / "get_symbols.py"

# `--profile release` is default
FLAGS = {
    "target/malware/spica.exe.do_not_exec": "--lto fat",
    # NOTE: Skip the two blackcat samples since I'm unable to find decent compilation flags...
    "target/malware/blackcat.elf.do_not_exec": "TODO",
    # Depends on `tui` whose default feature `termion` is not Windows-compatible so no dependency
    # graph expansion happens...
    "target/malware/blackcat.exe.do_not_exec": "TODO",
    "target/malware/rustystealer.exe.do_not_exec": "--lto fat",
    "target/malware/krustyloader.elf.do_not_exec": "--opt-level z --lto fat --codegen-units 1",
    "target/1.82.0/x86_64-unknown-linux-gnu/debug/rg": "--profile dev",
    "target/1.82.0/x86_64-unknown-linux-gnu/release/rg": "",
    "target/1.82.0/x86_64-unknown-linux-gnu/debug/just": "--profile dev",
    "target/1.82.0/x86_64-unknown-linux-gnu/release/just": "--lto fat --codegen-units 1",
    "target/1.82.0/x86_64-unknown-linux-gnu/debug/resvg": "--profile dev",
    "target/1.82.0/x86_64-unknown-linux-gnu/release/resvg": "",
}

with open(TARGET_PATH / "binaries.json") as f:
    binaries = json.loads(f.read())
    binaries = ChainMap(
        *[
            binaries[k]
            for k in binaries.keys()
            if k in ["oss_projects", "malware_samples"]
        ]
    )
    for b in binaries:
        assert b in FLAGS, f"missing flags for {b}"

for unstripped, stripped in binaries.items():
    if FLAGS[unstripped] == "TODO":
        continue

    print(unstripped)
    is_msvc = True if stripped.endswith(".pdb") else False

    rel_path = Path(unstripped).relative_to(TARGET_PATH)
    out_path = EVALUATION_PATH / rel_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    out_path_ref = out_path.absolute().with_suffix(out_path.suffix + ".reference")
    out_path_matched = out_path.absolute().with_suffix(
        out_path.suffix + ".matched_with_crates"
    )

    if unstripped != stripped:
        # Ground truth symbols; for MSVC this will autoload the .pdb
        if not out_path_ref.exists():
            subprocess.check_output(
                [
                    "ida",
                    "-c",  # Ignore old db
                    "-A",  # No dialog boxes
                    f"-S{IDA_SCRIPT_PATH} {out_path_ref} nomatch",
                    unstripped,
                ]
            )

    # Generate crate signatures
    sig_path = (SIGNATURES_PATH / rel_path).absolute()
    if not sig_path.exists():
        subprocess.check_output(
            [
                "rust-sig-gen",
                "-f",
                str(FLAIR_PATH),
                "-o",
                str(sig_path),
                "crates",
                stripped,
            ]
            + FLAGS[unstripped].split(),
        )

    # Symbols detected using signatures
    if not out_path_matched.exists():
        subprocess.check_output(
            [
                "ida",
                "-c",
                "-A",
                "-Opdb:off",  # Disable .pdb loading so we have no symbols a priori
                f"-S{IDA_SCRIPT_PATH} {out_path_matched} match {sig_path}",
                unstripped if is_msvc else stripped,
            ],
        )
