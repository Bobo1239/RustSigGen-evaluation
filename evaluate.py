#!/usr/bin/env python3

from pathlib import Path
import subprocess
import json

# NOTE: This assumes IDA Pro 9.0 (so the binary is just called `ida`)

# TODO: Would be cool to leverage the new idalib for this. But need to make plugin work optionally
#       without QT event loop.

TARGET_PATH = Path("target")
EVALUATION_PATH = TARGET_PATH / "evaluation"

IDA_SCRIPT_PATH = Path(__file__).parent / "ida_scripts" / "get_symbols.py"

with open(TARGET_PATH / "binaries.json") as f:
    binaries = json.loads(f.read())

for unstripped, stripped in binaries.items():
    print(unstripped)
    is_msvc = True if stripped.endswith(".pdb") else False

    rel_path = Path(unstripped).relative_to(TARGET_PATH)
    out_path = EVALUATION_PATH / rel_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    out_path_ref = out_path.absolute().with_suffix(out_path.suffix + ".reference")
    out_path_matched = out_path.absolute().with_suffix(out_path.suffix + ".matched")

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

    # Symbols detected using signatures
    if not out_path_matched.exists():
        subprocess.check_output(
            [
                "ida",
                "-c",
                "-A",
                "-Opdb:off",  # Disable .pdb loading so we have no symbols a priori
                f"-S{IDA_SCRIPT_PATH} {out_path_matched} match",
                unstripped if is_msvc else stripped,
            ],
        )
